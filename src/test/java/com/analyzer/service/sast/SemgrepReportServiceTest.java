package com.analyzer.service.sast;

import com.analyzer.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SemgrepReportServiceTest {
    @TempDir Path temp;
    private final SemgrepReportService service = new SemgrepReportService();

    @Test void readsCleanReportWithoutCallingItProofOfSafety() throws Exception {
        Path file = write("{\"results\": [], \"errors\": []}");
        var report = service.read(file);
        assertEquals(0, report.findings().size());
        assertFalse(report.hasErrors());
    }

    @Test void importsFindingWithAbsoluteFileLines() throws Exception {
        Path file = write("""
             {"results":[{"check_id":"java.test.rule", "path":"src/Foo.java",
               "start":{"line":12}, "end":{"line":14},
               "extra":{"severity":"ERROR", "message":"Sensitive call"}}],"errors":[]}
             """);
        var report = service.read(file);
        assertEquals(1, report.findings().size());
        Vulnerability vuln = service.toVulnerability(report.findings().getFirst());
        assertEquals("12-14", vuln.getLineRange());
        assertEquals("HIGH", vuln.getSeverity());
        assertEquals("SAST_REPORTED", vuln.getValidationStatus());
    }

    @Test void preservesDiagnosticErrorsInsteadOfCallingScanClean() throws Exception {
        Path file = write("{\"results\":[], \"errors\":[{\"message\":\"parsing failed\"}]}");
        assertTrue(service.read(file).hasErrors());
    }

    @Test void failsClosedForMalformedReport() throws Exception {
        Path file = write("{\"foo\":123}");
        assertThrows(IOException.class, () -> service.read(file));
    }

    @Test void refusesDirectoryTraversalOrWindowsAbsolutePath() throws Exception {
        assertThrows(IOException.class,
                () -> service.resolveInProject(temp, "../../outside.java"));
        assertThrows(IOException.class,
                () -> service.resolveInProject(temp, "C:\\Windows\\system.ini"));
    }

    @Test void resolvesProjectFileSafely() throws Exception {
        Path source = temp.resolve("src/Foo.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "class Foo {}\n");
        assertEquals(source.toRealPath(), service.resolveInProject(temp, "src/Foo.java"));
    }

    private Path write(String json) throws IOException {
        Path path = temp.resolve("report.json");
        Files.writeString(path, json);
        return path;
    }
}
