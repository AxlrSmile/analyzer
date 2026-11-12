package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.parser.CodeChunk;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.sast.FindingCorrelationService;
import com.analyzer.service.sast.SemgrepCliService;
import com.analyzer.service.sast.SemgrepReportService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class UnifiedPartialScanTest {
    @TempDir Path root;

    @Test void oneChunkFailureKeepsOtherChunkFindingAndReportsPartial() throws Exception {
        File disk = Files.writeString(root.resolve("Demo.java"), "line one\nline two\n").toFile();
        SourceFile source = new SourceFile("Demo.java", disk.toPath(), "Demo.java", 2, "line one\nline two\n");
        FileAnalyzer analyzer = mock(FileAnalyzer.class);
        CodeParser parser = mock(CodeParser.class);
        SecurityScannerAgent agent = mock(SecurityScannerAgent.class);
        SemgrepCliService semgrep = mock(SemgrepCliService.class);
        FindingCorrelationService correlation = mock(FindingCorrelationService.class);
        when(analyzer.analyzeFile(any(File.class))).thenReturn(source);
        var first = new CodeChunk("line one", 1, 1);
        var second = new CodeChunk("line two", 2, 2);
        when(parser.splitIntoLocatedChunks(source)).thenReturn(List.of(first, second));
        Vulnerability candidate = new Vulnerability("Test", "HIGH", "1", "context", "review");
        when(agent.scanLocatedChunk(eq(first), anyString(), anyString())).thenReturn(List.of(candidate));
        when(agent.scanLocatedChunk(eq(second), anyString(), anyString())).thenThrow(new IllegalStateException("bad response"));
        when(semgrep.scan(any(Path.class), anyList())).thenReturn(new SemgrepReportService.Report(List.of(), List.of()));
        when(correlation.merge(any(Path.class), anyList(), any())).thenReturn(new FindingCorrelationService.Summary(0,0,0));
        var result = new UnifiedScanService(analyzer, parser, agent, semgrep, correlation)
                .scan(root, List.of(disk), "local");
        assertEquals(0, result.analyzedByLlm());
        assertEquals(1, result.partialByLlm());
        assertEquals(0, result.failedByLlm());
        assertEquals(1, result.files().getFirst().getVulnerabilities().size());
        assertEquals(List.of("Demo.java"), result.partialFiles());
        assertTrue(result.diagnostics().stream().anyMatch(d -> d.contains("bad response")));
    }

    @Test void unverifiedEvidenceMarksWholeFilePartialNotClean() throws Exception {
        File disk = Files.writeString(root.resolve("Demo.java"), "line one\n").toFile();
        SourceFile source = new SourceFile("Demo.java", disk.toPath(), "Demo.java", 1, "line one\n");
        FileAnalyzer analyzer = mock(FileAnalyzer.class);
        CodeParser parser = mock(CodeParser.class);
        SecurityScannerAgent agent = mock(SecurityScannerAgent.class);
        SemgrepCliService semgrep = mock(SemgrepCliService.class);
        FindingCorrelationService correlation = mock(FindingCorrelationService.class);
        when(analyzer.analyzeFile(any(File.class))).thenReturn(source);
        when(parser.splitIntoLocatedChunks(source)).thenReturn(List.of(new CodeChunk("line one", 1, 1)));
        Vulnerability candidate = new Vulnerability("Test", "HIGH", "1", "context", "review");
        candidate.setModelOutputStatus("EVIDENCE_UNVERIFIED");
        when(agent.scanLocatedChunk(any(CodeChunk.class), anyString(), anyString())).thenReturn(List.of(candidate));
        when(semgrep.scan(any(Path.class), anyList())).thenReturn(new SemgrepReportService.Report(List.of(), List.of()));
        when(correlation.merge(any(Path.class), anyList(), any())).thenReturn(new FindingCorrelationService.Summary(0,0,0));
        var result = new UnifiedScanService(analyzer, parser, agent, semgrep, correlation)
                .scan(root, List.of(disk), "local");
        assertEquals(1, result.partialByLlm());
        assertEquals(0, result.failedByLlm());
        assertEquals(1, result.files().getFirst().getVulnerabilities().size());
    }
}
