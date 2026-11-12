package com.analyzer.service.fix;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class FixRecommendationAgentTest {
    @TempDir Path dir;

    private SourceFile scanned(String original) throws IOException {
        Path path = Files.writeString(dir.resolve("Example.java"), original);
        var file = new SourceFile("Example.java", path, "Example.java", 1, original);
        Vulnerability finding = new Vulnerability("SQL injection", "HIGH", "1", "String concatenation", "Use query parameters");
        finding.setCwe("CWE-89");
        file.setVulnerabilities(List.of(finding));
        return file;
    }

    @Test void createsSuggestionWithoutTouchingOriginalAndIncludesEvidence() throws Exception {
        String original = "class Example { String sql = \"SELECT \" + input; }\n";
        var file = scanned(original);
        OllamaClient ollama = mock(OllamaClient.class);
        when(ollama.chatWithModel(eq("qwen2.5-coder:7b"), anyString()))
                .thenReturn("```java\nclass Example { String sql = \"SELECT ?\"; }\n```");
        FixProposal proposal = new FixRecommendationAgent(ollama).propose(file, "qwen2.5-coder:7b");
        assertTrue(proposal.proposedContent().contains("SELECT ?"));
        assertEquals(original, Files.readString(file.getPath()));
        assertEquals(file.getPath().toRealPath(), proposal.sourcePath());
        assertTrue(proposal.diffPreview().contains("+"));
        verify(ollama).chatWithModel(eq("qwen2.5-coder:7b"), argThat(prompt ->
                prompt.contains("CWE-89") && prompt.contains("Use query parameters")
                        && prompt.contains("[BEGIN SOURCE]")));
    }

    @Test void refusesStaleSourceBeforeCallingModel() throws Exception {
        var file = scanned("class Example {}\n");
        Files.writeString(file.getPath(), "class Example { int x; }\n");
        OllamaClient ollama = mock(OllamaClient.class);
        assertThrows(IOException.class, () -> new FixRecommendationAgent(ollama).propose(file, "model"));
        verifyNoInteractions(ollama);
    }

    @Test void refusesIdenticalCandidate() throws Exception {
        var file = scanned("class Example {}\n");
        OllamaClient ollama = mock(OllamaClient.class);
        when(ollama.chatWithModel(anyString(), anyString())).thenReturn("class Example {}\n");
        assertThrows(IOException.class, () -> new FixRecommendationAgent(ollama).propose(file, "model"));
    }

    @Test void flagsUnverifiedFindingForManualReview() throws Exception {
        var file = scanned("class Example {}\n");
        file.getVulnerabilities().getFirst().setMechanismStatus("DEFENSE_PRESENT");
        OllamaClient ollama = mock(OllamaClient.class);
        when(ollama.chatWithModel(anyString(), anyString())).thenReturn("class Example { int x; }\n");
        FixProposal proposal = new FixRecommendationAgent(ollama).propose(file, "model");
        assertTrue(proposal.reviewNotes().contains("ложные тревоги"));
    }

    @Test void requiresFindingAndRealFile() throws Exception {
        var file = scanned("class Example {}\n");
        file.setVulnerabilities(List.of());
        OllamaClient ollama = mock(OllamaClient.class);
        assertThrows(IOException.class, () -> new FixRecommendationAgent(ollama).propose(file, "model"));
        verifyNoInteractions(ollama);
    }

    @Test void extractOnlySingleCodeBlock() throws Exception {
        assertEquals("class A {}", FixRecommendationAgent.extractCode("```java\nclass A {}\n```"));
        assertEquals("class A {}", FixRecommendationAgent.extractCode("class A {}"));
        assertThrows(IOException.class, () -> FixRecommendationAgent.extractCode("```java\nclass A {}"));
        assertThrows(IOException.class, () -> FixRecommendationAgent.extractCode(""));
        assertThrows(IOException.class, () -> FixRecommendationAgent.extractCode("```java\nclass A {}\n```\nextra"));
    }
}
