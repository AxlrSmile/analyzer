package com.analyzer.service.agent;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SecurityReviewerAgentTest {
    private OllamaClient ollama;
    private SecurityReviewerAgent reviewer;
    private SourceFile file;
    private Vulnerability finding;

    @BeforeEach void init() {
        ollama = mock(OllamaClient.class);
        reviewer = new SecurityReviewerAgent(ollama, new ObjectMapper());
        file = new SourceFile("Demo.java", Path.of("Demo.java"), "Demo.java", 4,
                "class Demo {\n  void go() {\n    runSomething();\n  }\n}\n");
        finding = new Vulnerability("Semgrep: process-builder", "HIGH", "3",
                "Потенциально недоверенный аргумент", "Проверить источник данных");
        finding.setValidationStatus("SAST_REPORTED");
    }

    @Test void keepsSastFindingAndMarksLikelyFalsePositive() {
        when(ollama.chatWithModel(eq("qwen2.5-coder:7b"), anyString())).thenReturn(
                "{\"verdict\":\"LIKELY_FALSE_POSITIVE\","
                        + "\"rationale\":\"Нет признаков вызова командной оболочки в показанном коде\","
                        + "\"evidenceLines\":[2,3]}");
        var result = reviewer.review(file, finding, "qwen2.5-coder:7b");
        assertEquals("LIKELY_FALSE_POSITIVE", result.verdict());
        assertEquals("SAST_REPORTED", finding.getValidationStatus());
        assertTrue(finding.getValidationStatusLabel().contains("ложная тревога"));
        assertTrue(finding.getAiReviewNote().contains("экспертная проверка"));
        verify(ollama).chatWithModel(eq("qwen2.5-coder:7b"), contains("3 |     runSomething();"));
    }

    @Test void acceptsLikelyTruePositiveWithoutUpgradingSeverity() {
        when(ollama.chatWithModel(any(), anyString())).thenReturn(
                "{\"verdict\":\"LIKELY_TRUE_POSITIVE\",\"rationale\":\"Вход проходит без ограничений\",\"evidenceLines\":[3]}");
        reviewer.review(file, finding, "local");
        assertEquals("LIKELY_TRUE_POSITIVE", finding.getAiReviewStatus());
        assertEquals("HIGH", finding.getSeverity());
    }

    @Test void acceptsFencedNeedsReviewResponse() {
        when(ollama.chatWithModel(any(), anyString())).thenReturn("""
                ```json
                {"verdict":"NEEDS_REVIEW","rationale":"Нет данных о вызывающем коде","evidenceLines":[]}
                ```
                """);
        assertEquals("NEEDS_REVIEW", reviewer.review(file, finding, "local").verdict());
    }

    @Test void rejectsInventedLineNumbersWithoutChangingOriginalFinding() {
        when(ollama.chatWithModel(any(), anyString())).thenReturn(
                "{\"verdict\":\"LIKELY_FALSE_POSITIVE\",\"rationale\":\"No shell\",\"evidenceLines\":[999]}");
        assertThrows(IllegalStateException.class, () -> reviewer.review(file, finding, "local"));
        assertEquals("NOT_REVIEWED", finding.getAiReviewStatus());
        assertEquals("SAST_REPORTED", finding.getValidationStatus());
    }

    @Test void rejectsUnexpectedVerdict() {
        when(ollama.chatWithModel(any(), anyString())).thenReturn(
                "{\"verdict\":\"CONFIRMED_SAFE\",\"rationale\":\"Safe\",\"evidenceLines\":[]}");
        assertThrows(IllegalStateException.class, () -> reviewer.review(file, finding, "local"));
    }

    @Test void rejectsMissingEvidenceArrayAndBrokenJson() {
        assertThrows(IllegalStateException.class, () -> reviewer.parseResponse(
                "{\"verdict\":\"NEEDS_REVIEW\",\"rationale\":\"unknown\"}", 1, 5));
        assertThrows(IllegalStateException.class, () -> reviewer.parseResponse("not json", 1, 5));
    }

    @Test void refusesToReviewNonSemgrepFinding() {
        finding.setValidationStatus("LOCATION_CHECKED");
        assertThrows(IllegalArgumentException.class, () -> reviewer.review(file, finding, "local"));
        verifyNoInteractions(ollama);
    }

    @Test void refusesInvalidSourcePositionWithoutContactingModel() {
        finding.setLineRange("500");
        assertThrows(IllegalArgumentException.class, () -> reviewer.review(file, finding, "local"));
        verifyNoInteractions(ollama);
    }
}
