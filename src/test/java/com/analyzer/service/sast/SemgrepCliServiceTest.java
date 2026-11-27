package com.analyzer.service.sast;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SemgrepCliServiceTest {
    @TempDir Path project;

    @Test void generatesShellFreeCommandWithExplicitRulePackAndSelectedFile() throws Exception {
        Path source = Files.writeString(project.resolve("with space.java"), "class Test {}\n");
        var command = SemgrepCliService.buildCommand(Path.of("semgrep"), project,
                List.of(source), project.resolve("report.json"));
        assertEquals("semgrep", command.getFirst());
        assertTrue(command.contains("p/default"));
        assertTrue(command.contains("--no-git-ignore"));
        assertTrue(command.contains("off"));
        assertEquals("./with space.java", command.getLast());
        assertFalse(command.contains("--autofix"));
    }

    @Test void deniesPathsOutsideProject() throws Exception {
        Path outside = Files.createTempFile("other", ".java");
        try {
            assertThrows(IOException.class, () -> SemgrepCliService.buildCommand(
                    Path.of("semgrep"), project, List.of(outside), project.resolve("report.json")));
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    @Test void deniesEmptySelection() {
        assertThrows(IOException.class, () -> SemgrepCliService.buildCommand(
                Path.of("semgrep"), project, List.of(), project.resolve("report.json")));
    }
}
