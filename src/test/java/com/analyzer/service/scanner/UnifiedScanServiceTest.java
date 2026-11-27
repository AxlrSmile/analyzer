package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.agent.SecurityReviewerAgent;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.CodeChunk;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.sast.FindingCorrelationService;
import com.analyzer.service.sast.SemgrepCliService;
import com.analyzer.service.sast.SemgrepReportService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class UnifiedScanServiceTest {
    @TempDir Path project;
    private FileAnalyzer fileAnalyzer;
    private CodeParser parser;
    private SecurityScannerAgent agent;
    private SemgrepCliService semgrep;
    private FindingCorrelationService correlation;
    private UnifiedScanService service;

    @BeforeEach void init() {
        fileAnalyzer = mock(FileAnalyzer.class);
        parser = mock(CodeParser.class);
        agent = mock(SecurityScannerAgent.class);
        semgrep = mock(SemgrepCliService.class);
        correlation = mock(FindingCorrelationService.class);
        service = new UnifiedScanService(fileAnalyzer, parser, agent, semgrep, correlation);
    }

    private File setupFile() throws Exception {
        File file = Files.writeString(project.resolve("Safe.java"), "class Safe {}\n").toFile();
        SourceFile source = new SourceFile("Safe.java", file.toPath(), "Safe.java", 1, "class Safe {}\n");
        when(fileAnalyzer.analyzeFile(any(File.class))).thenReturn(source);
        when(parser.splitIntoLocatedChunks(source)).thenReturn(
                List.of(new CodeChunk("class Safe {}\n", 1, 1)));
        when(agent.scanLocatedChunk(any(CodeChunk.class), anyString(), anyString()))
                .thenReturn(List.of());
        when(semgrep.scan(any(Path.class), anyList())).thenReturn(new SemgrepReportService.Report(List.of(), List.of()));
        when(correlation.merge(any(Path.class), anyList(), any())).thenReturn(
                new FindingCorrelationService.Summary(0, 0, 0));
        return file;
    }

    @Test void checksSastAndLlmThroughOneCall() throws Exception {
        File file = setupFile();
        var result = service.scan(project, List.of(file), "local-model");
        assertEquals(1, result.analyzedByLlm());
        assertEquals(0, result.failedByLlm());
        assertTrue(result.sastCompleted());
        assertEquals(1, result.files().size());
        verify(agent).scanLocatedChunk(
                eq(new CodeChunk("class Safe {}\n", 1, 1)), eq("Safe.java"), eq("local-model"));
        verify(semgrep).scan(any(Path.class), anyList());
    }

    @Test void doesNotCallSastFailureAZeroFindingScan() throws Exception {
        File file = setupFile();
        when(semgrep.scan(any(Path.class), anyList())).thenThrow(new IOException("offline"));
        var result = service.scan(project, List.of(file), "local-model");
        assertFalse(result.sastCompleted());
        assertEquals(1, result.analyzedByLlm());
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.contains("offline")));
        verifyNoInteractions(correlation);
    }

    @Test void preservesSastCheckWhenLlmFails() throws Exception {
        File file = setupFile();
        when(agent.scanLocatedChunk(any(CodeChunk.class), anyString(), anyString()))
                .thenThrow(new IllegalStateException("model unavailable"));
        var result = service.scan(project, List.of(file), "local-model");
        assertTrue(result.sastCompleted());
        assertEquals(1, result.failedByLlm());
        assertEquals(0, result.analyzedByLlm());
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.contains("model unavailable")));
        verify(correlation).merge(any(Path.class), anyList(), any());
    }

    @Test void emptyLocatedChunksAreNotReportedAsSuccessfulLlmAnalysis() throws Exception {
        File file = setupFile();
        when(parser.splitIntoLocatedChunks(any(SourceFile.class))).thenReturn(List.of());
        var result = service.scan(project, List.of(file), "local-model");
        assertEquals(0, result.analyzedByLlm());
        assertEquals(1, result.failedByLlm());
        assertTrue(result.sastCompleted());
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.contains("не вернул фрагменты")));
        verifyNoInteractions(agent);
    }

    @Test void reviewsSastFindingAfterCorrelation() throws Exception {
        File sourcePath = setupFile();
        SecurityReviewerAgent reviewer = mock(SecurityReviewerAgent.class);
        service = new UnifiedScanService(fileAnalyzer, parser, agent, semgrep, correlation, reviewer);
        when(correlation.merge(any(Path.class), anyList(), any())).thenAnswer(inv -> {
            List<SourceFile> sources = inv.getArgument(1);
            Vulnerability item = new Vulnerability("Semgrep: rule", "HIGH", "1", "desc", "check");
            item.setValidationStatus("SAST_REPORTED");
            sources.get(0).getVulnerabilities().add(item);
            return new FindingCorrelationService.Summary(1, 0, 0);
        });
        var result = service.scan(project, List.of(sourcePath), "qwen2.5-coder:7b");
        assertEquals(1, result.aiReviewed());
        assertEquals(0, result.aiReviewFailed());
        verify(reviewer).review(any(SourceFile.class), any(Vulnerability.class), eq("qwen2.5-coder:7b"));
    }

    @Test void reviewerFailureDoesNotDeleteSastFinding() throws Exception {
        File sourcePath = setupFile();
        SecurityReviewerAgent reviewer = mock(SecurityReviewerAgent.class);
        service = new UnifiedScanService(fileAnalyzer, parser, agent, semgrep, correlation, reviewer);
        when(correlation.merge(any(Path.class), anyList(), any())).thenAnswer(inv -> {
            List<SourceFile> sources = inv.getArgument(1);
            Vulnerability item = new Vulnerability("Semgrep: rule", "HIGH", "1", "desc", "check");
            item.setValidationStatus("SAST_REPORTED");
            sources.get(0).getVulnerabilities().add(item);
            return new FindingCorrelationService.Summary(1, 0, 0);
        });
        doThrow(new IllegalStateException("bad JSON")).when(reviewer)
                .review(any(SourceFile.class), any(Vulnerability.class), anyString());
        var result = service.scan(project, List.of(sourcePath), "local");
        assertEquals(0, result.aiReviewed());
        assertEquals(1, result.aiReviewFailed());
        assertEquals(1, result.files().get(0).getVulnerabilities().size());
        assertEquals("NEEDS_REVIEW", result.files().get(0).getVulnerabilities().get(0).getAiReviewStatus());
        assertTrue(result.diagnostics().stream().anyMatch(x -> x.contains("bad JSON")));
    }

    @Test void excludesNonCodeFileFromBothScanners() throws Exception {
        File code = setupFile();
        File wheel = Files.writeString(project.resolve("installer.whl"), "binary").toFile();
        var result = service.scan(project, List.of(code, wheel), "local-model");
        assertEquals(1, result.skippedTargets());
        assertEquals(1, result.files().size());
        verify(semgrep).scan(any(Path.class), argThat(paths -> paths.size() == 1));
    }
}
