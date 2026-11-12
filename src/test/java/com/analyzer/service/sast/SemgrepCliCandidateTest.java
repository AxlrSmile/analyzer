package com.analyzer.service.sast;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class SemgrepCliCandidateTest {
    @TempDir Path project;

    @Test void rejectsCandidateNamesWithTraversalAndTooLongCode() {
        SemgrepCliService semgrep = new SemgrepCliService(new SemgrepReportService());
        assertThrows(IOException.class, () -> semgrep.scanTemporaryCandidate(
                project, "../other.java", "class A {}"));
        assertThrows(IOException.class, () -> semgrep.scanTemporaryCandidate(
                project, "sub\\\\folder.java", "class A {}"));
        assertThrows(IOException.class, () -> semgrep.scanTemporaryCandidate(
                project, "A.java", "a".repeat(1_000_001)));
    }
}
