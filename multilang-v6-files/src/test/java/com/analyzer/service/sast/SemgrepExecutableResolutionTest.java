package com.analyzer.service.sast;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SemgrepExecutableResolutionTest {
    @TempDir Path trustedAnalyzerHome;

    @Test
    void resolvesSemgrepFromTrustedAnalyzerHome() throws Exception {
        Path scripts = Files.createDirectories(trustedAnalyzerHome.resolve(".venv-semgrep/Scripts"));
        Path executable = Files.writeString(scripts.resolve("semgrep.exe"), "test placeholder");
        assertEquals(executable.toAbsolutePath(),
                SemgrepCliService.locateExecutable(trustedAnalyzerHome, ""));
    }

    @Test
    void explicitExecutableOverridesTrustedHome() throws Exception {
        Path scripts = Files.createDirectories(trustedAnalyzerHome.resolve(".venv-semgrep/Scripts"));
        Files.writeString(scripts.resolve("semgrep.exe"), "placeholder");
        Path override = trustedAnalyzerHome.resolve("a directory with spaces/custom-semgrep.exe");
        assertEquals(override,
                SemgrepCliService.locateExecutable(trustedAnalyzerHome, override.toString()));
    }

    @Test
    void fallsBackToTrustedPathWhenNotInstalledInAnalyzerHome() {
        assertEquals(Path.of("semgrep"),
                SemgrepCliService.locateExecutable(trustedAnalyzerHome, ""));
    }
}
