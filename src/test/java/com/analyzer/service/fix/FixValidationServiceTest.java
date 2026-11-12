package com.analyzer.service.fix;

import com.analyzer.service.sast.SemgrepCliService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class FixValidationServiceTest {
    @TempDir Path folder;

    private FixValidationService service() {
        return new FixValidationService(new FixReviewService(mock(SemgrepCliService.class)));
    }

    private FixProposal proposal(String filename, String original, String proposed) throws Exception {
        Path path = Files.writeString(folder.resolve(filename), original, StandardCharsets.UTF_8);
        return new FixProposal(path.toRealPath(), FixReviewService.hash(Files.readAllBytes(path)),
                original, proposed, "qwen2.5-coder:7b", "review required", "preview");
    }

    @Test void candidateThatCompilesAndPreservesApiPassesPreliminaryChecks() throws Exception {
        var before = "public class Example { public int calc(int x) { return x + 1; } }";
        var after = "public class Example { public int calc(int x) { return Math.addExact(x, 1); } }";
        var p = proposal("Example.java", before, after);
        var result = service().validate(p);
        assertEquals(FixValidationService.Status.PASSED, result.compilation());
        assertEquals(FixValidationService.Status.PASSED, result.api());
        assertEquals(FixValidationService.Status.PASSED, result.overall());
        assertEquals(before, Files.readString(p.sourcePath()));
        assertTrue(result.asText(p).contains("не означает доказанную безопасность"));
    }

    @Test void reproducedCase002MissingBaseVariableIsRejectedEvenWithoutSemgrepFinding() throws Exception {
        String original = """
                package benchmark.cases;
                import java.io.*;
                import java.nio.file.*;
                public class Case002 {
                    public String load(Path base, String requested) throws IOException {
                        return Files.readString(base.resolve(requested));
                    }
                }
                """;
        String candidate = """
                package benchmark.cases;
                import java.io.*;
                import java.nio.file.*;
                public class Case002 {
                    public String load(Path base, String requested) throws IOException {
                        Path file = base.resolve(requested);
                        if (!isValidPath(file)) throw new SecurityException();
                        return Files.readString(file);
                    }
                    private boolean isValidPath(Path path) {
                        return path.normalize().startsWith(base);
                    }
                }
                """;
        var result = service().validate(proposal("Case002.java", original, candidate));
        assertEquals(FixValidationService.Status.FAILED, result.compilation());
        assertEquals(FixValidationService.Status.FAILED, result.overall());
        assertTrue(result.details().contains("base"));
    }

    @Test void case008PreparedStatementCompilesWithPublicSignaturePreserved() throws Exception {
        String before = """
                package benchmark.cases;
                import java.sql.*;
                public class Case008 {
                    public ResultSet find(Connection c, String username) throws SQLException {
                        return c.createStatement().executeQuery("SELECT id FROM users WHERE username='" + username + "'");
                    }
                }
                """;
        String after = """
                package benchmark.cases;
                import java.sql.*;
                public class Case008 {
                    public ResultSet find(Connection c, String username) throws SQLException {
                        PreparedStatement p = c.prepareStatement("SELECT id FROM users WHERE username=?");
                        p.setString(1, username);
                        return p.executeQuery();
                    }
                }
                """;
        var result = service().validate(proposal("Case008.java", before, after));
        assertEquals(FixValidationService.Status.PASSED, result.overall());
    }

    @Test void changingPublicMethodSignatureFailsApiCheckThoughBothCompile() throws Exception {
        String original = "public class Sample { public int get(int x) { return x; } }";
        String changed = "public class Sample { public int get(String x) { return 1; } }";
        var result = service().validate(proposal("Sample.java", original, changed));
        assertEquals(FixValidationService.Status.PASSED, result.compilation());
        assertEquals(FixValidationService.Status.FAILED, result.api());
        assertEquals(FixValidationService.Status.FAILED, result.overall());
    }

    @Test void changingPackageIsRejected() throws Exception {
        var result = service().validate(proposal("Example.java",
                "package a; public class Example {}", "package b; public class Example {}"));
        assertEquals(FixValidationService.Status.FAILED, result.api());
        assertEquals(FixValidationService.Status.FAILED, result.overall());
    }

    @Test void externalDependenciesMeanNotCheckedNotIncorrectlyFailed() throws Exception {
        String original = "package demo; import com.example.External; public class Example {"
                + " public External fetch() { return null; } }";
        String candidate = "package demo; import com.example.External; public class Example {"
                + " public External fetch() { return (External) null; } }";
        var result = service().validate(proposal("Example.java", original, candidate));
        assertEquals(FixValidationService.Status.NOT_CHECKED, result.compilation());
        assertEquals(FixValidationService.Status.NOT_CHECKED, result.overall());
    }

    @Test void rejectsStaleSourceBeforeCompile() throws Exception {
        var p = proposal("Example.java", "public class Example {}", "public class Example { int x; }");
        Files.writeString(p.sourcePath(), "public class Example { int changed; }");
        assertThrows(IOException.class, () -> service().validate(p));
    }

    @Test void rejectsEmptyAndOversizedCandidate() throws Exception {
        var p = proposal("Example.java", "public class Example {}", " ");
        assertThrows(IOException.class, () -> service().validate(p));
        var large = proposal("L.java", "class L {}", "class L {} /*" + "a".repeat(1_000_100) + "*/");
        assertThrows(IOException.class, () -> service().validate(large));
    }

    @Test void unsupportedFileReturnsNotChecked() throws Exception {
        var result = service().validate(proposal("Example.txt", "hello", "world"));
        assertEquals(FixValidationService.Status.NOT_CHECKED, result.overall());
    }

    @Test void compilerDoesNotRunGeneratedStaticInitializer() throws Exception {
        Path marker = folder.resolve("should-never-be-created.txt");
        String escaped = marker.toString().replace("\\", "\\\\");
        String code = "public class Sample { static { try { java.nio.file.Files.writeString("
                + "java.nio.file.Path.of(\"" + escaped + "\"), \"bad\"); }"
                + " catch (Exception e) {} } public int run() { return 2; } }";
        var result = service().validate(proposal("Sample.java",
                "public class Sample { public int run() { return 1; } }", code));
        assertEquals(FixValidationService.Status.PASSED, result.overall());
        assertFalse(Files.exists(marker), "javac must never execute user-supplied static initializers");
    }

    @Test void removedPublicClassIsRejected() throws Exception {
        var p = proposal("Sample.java", "public class Sample { public int n() { return 1; } }",
                "class Sample { public int n() { return 2; } }");
        // Changing top-level visibility requires a manual review even if signatures remain similar.
        var result = service().validate(p);
        assertEquals(FixValidationService.Status.PASSED, result.compilation());
        // The API parser tracks declared types; javac alone does not prove visibility.
        assertEquals(FixValidationService.Status.FAILED, result.api());
    }
}
