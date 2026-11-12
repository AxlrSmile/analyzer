package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityScannerAgentTest {

    private OllamaClient ollamaClient;
    private SecurityScannerAgent agent;

    @BeforeEach
    void setup() {
        ollamaClient = mock(OllamaClient.class);
        agent = new SecurityScannerAgent(ollamaClient);
    }

    @Test
    void forwardsSelectedModelAndNormalizesSeverity() {
        Vulnerability finding = new Vulnerability(
                "SQL Injection", "high", "4", "Untrusted input in SQL",
                "Use parameterized queries");
        when(ollamaClient.analyzeCodeChunk("code", "Java", "test-model"))
                .thenReturn(List.of(finding));

        List<Vulnerability> result = agent.scanChunk("code", "Java", "test-model");

        assertEquals(1, result.size());
        assertEquals("HIGH", result.getFirst().getSeverity());
        verify(ollamaClient).analyzeCodeChunk("code", "Java", "test-model");
    }

    @Test
    void cleanResponseRemainsEmpty() {
        when(ollamaClient.analyzeCodeChunk("code", "Java", "model"))
                .thenReturn(List.of());
        assertTrue(agent.scanChunk("code", "Java", "model").isEmpty());
    }

    @Test
    void ollamaFailureCannotBeMistakenForCleanCode() {
        when(ollamaClient.analyzeCodeChunk("code", "Java", "model"))
                .thenThrow(new IllegalStateException("Ollama unavailable"));
        assertThrows(IllegalStateException.class,
                () -> agent.scanChunk("code", "Java", "model"));
    }

    @Test
    void malformedFindingIsRejected() {
        Vulnerability finding = new Vulnerability(
                "SQL Injection", "UNKNOWN", "4", "Untrusted input",
                "Use parameterized queries");
        when(ollamaClient.analyzeCodeChunk("code", "Java", "model"))
                .thenReturn(List.of(finding));
        assertThrows(IllegalStateException.class,
                () -> agent.scanChunk("code", "Java", "model"));
    }

    @Test
    void blankCodeDoesNotCallModel() {
        assertTrue(agent.scanChunk(" ", "Java", "model").isEmpty());
        verifyNoInteractions(ollamaClient);
    }

    @Test
    void scannerRunsLocationValidationAfterLlm() {
        Vulnerability v = new Vulnerability(
                "Potential SQL injection", "HIGH", "50", "Unsafe construction",
                "Use parameterized queries");
        when(ollamaClient.analyzeCodeChunk("code", "Java", "model"))
                .thenReturn(List.of(v));
        List<Vulnerability> results = agent.scanChunk("code", "Java", "model");
        assertEquals(1, results.size());
        assertEquals("NEEDS_REVIEW", results.getFirst().getValidationStatus());
    }
}
