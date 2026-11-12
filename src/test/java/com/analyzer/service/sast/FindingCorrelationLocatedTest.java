package com.analyzer.service.sast;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class FindingCorrelationLocatedTest {
    @TempDir Path project;
    private final FindingCorrelationService service = new FindingCorrelationService(new SemgrepReportService());

    private SourceFile source(boolean verified) throws Exception {
        Path file = project.resolve("Long.java");
        String content = "source line\n".repeat(180);
        Files.writeString(file, content);
        SourceFile source = new SourceFile("Long.java", file, "Long.java", 180, content);
        Vulnerability candidate = new Vulnerability("Command Injection", "HIGH", "90", "Details", "Review");
        candidate.setValidationStatus("LOCATION_CHECKED");
        candidate.setAbsoluteLineNumbers(verified);
        source.setVulnerabilities(new ArrayList<>(List.of(candidate)));
        return source;
    }

    private SemgrepReportService.Report report() {
        return new SemgrepReportService.Report(List.of(
                new SemgrepReportService.Finding("rule", "Long.java", 90, 90, "ERROR", "Match")), List.of());
    }

    @Test void longFileCanCorrelateVerifiedAbsoluteLines() throws Exception {
        SourceFile file = source(true);
        var summary = service.merge(project, List.of(file), report());
        assertEquals(1, summary.overlaps());
        assertEquals("POSSIBLE_SAST_MATCH", file.getVulnerabilities().getFirst().getValidationStatus());
    }

    @Test void neverCorrelatesGuessedLongFileCoordinates() throws Exception {
        SourceFile file = source(false);
        var summary = service.merge(project, List.of(file), report());
        assertEquals(0, summary.overlaps());
    }
}
