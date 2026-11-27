package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.CodeParserImpl;
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

/** Verifies chunk metadata -> validation -> deduplication -> SAST correlation. */
class UnifiedScanLocatedIntegrationTest {
    @TempDir Path project;

    @Test void twoOverlappingChunksBecomeOneVerifiedAbsoluteFinding() throws Exception {
        String content = "line\n".repeat(180);
        File disk = Files.writeString(project.resolve("Long.java"), content).toFile();
        SourceFile source = new SourceFile("Long.java", disk.toPath(), "Long.java", 180, content);

        FileAnalyzer fileAnalyzer = mock(FileAnalyzer.class);
        when(fileAnalyzer.analyzeFile(any(File.class))).thenReturn(source);
        OllamaClient ollama = mock(OllamaClient.class);
        // The same issue on original source line 90 appears in BOTH chunks.
        when(ollama.analyzeCodeChunk(anyString(), eq("Long.java"), eq("qwen2.5-coder:7b")))
                .thenAnswer(inv -> List.of(new Vulnerability(
                        "Potential Injection", "HIGH", "90", "Evidence", "Review")));
        SecurityScannerAgent agent = new SecurityScannerAgent(ollama);

        SemgrepCliService semgrep = mock(SemgrepCliService.class);
        when(semgrep.scan(any(Path.class), anyList())).thenReturn(new SemgrepReportService.Report(
                List.of(new SemgrepReportService.Finding(
                        "test.rule", "Long.java", 90, 90, "ERROR", "SAST finding")), List.of()));
        FindingCorrelationService correlation = new FindingCorrelationService(new SemgrepReportService());
        var service = new UnifiedScanService(fileAnalyzer, new CodeParserImpl(), agent,
                semgrep, correlation);

        var result = service.scan(project, List.of(disk), "qwen2.5-coder:7b");
        assertEquals(1, result.analyzedByLlm());
        assertEquals(1, result.possibleOverlaps());
        assertEquals(2, result.files().getFirst().getVulnerabilities().size());
        Vulnerability candidate = result.files().getFirst().getVulnerabilities().getFirst();
        assertEquals("90", candidate.getLineRange());
        assertEquals("POSSIBLE_SAST_MATCH", candidate.getValidationStatus());
        assertTrue(candidate.hasAbsoluteLineNumbers());
        verify(ollama, times(2)).analyzeCodeChunk(anyString(), eq("Long.java"), eq("qwen2.5-coder:7b"));
    }
}
