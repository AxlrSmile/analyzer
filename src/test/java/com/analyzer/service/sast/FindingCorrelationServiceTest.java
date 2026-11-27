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

class FindingCorrelationServiceTest {
    @TempDir Path project;
    private final FindingCorrelationService service = new FindingCorrelationService(new SemgrepReportService());

    @Test void marksMatchingLinesAsPossibleNotConfirmed() throws Exception {
        SourceFile file = source("src/Example.java", "first\nsecond\nthird\n", "2");
        var summary = service.merge(project, List.of(file), report("src/Example.java", 2, 2));
        assertEquals(1, summary.imported());
        assertEquals(1, summary.overlaps());
        assertEquals("POSSIBLE_SAST_MATCH", file.getVulnerabilities().getFirst().getValidationStatus());
        assertEquals("SAST_REPORTED", file.getVulnerabilities().get(1).getValidationStatus());
        assertTrue(file.getVulnerabilities().getFirst().getValidationNote().contains("не подтверждённая"));
    }

    @Test void doesNotGuessAbsoluteLineNumbersForLongChunks() throws Exception {
        SourceFile file = source("Long.java", "row\n".repeat(101), "2");
        var summary = service.merge(project, List.of(file), report("Long.java", 2, 2));
        assertEquals(0, summary.overlaps());
        assertEquals("LOCATION_CHECKED", file.getVulnerabilities().getFirst().getValidationStatus());
    }

    @Test void doesNotCorrelateUnrelatedLines() throws Exception {
        SourceFile file = source("Small.java", "1\n2\n3\n", "1");
        var summary = service.merge(project, List.of(file), report("Small.java", 3, 3));
        assertEquals(0, summary.overlaps());
        assertEquals(2, file.getVulnerabilities().size());
    }

    @Test void rejectsReportPathsOutsideSelectedProject() throws Exception {
        SourceFile file = source("Small.java", "one\n", "1");
        var summary = service.merge(project, List.of(file), report("../outside.java", 1, 1));
        assertEquals(0, summary.imported());
        assertEquals(1, summary.unrelated());
    }

    private SourceFile source(String relative, String content, String range) throws Exception {
        Path file = project.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        SourceFile source = new SourceFile(file.getFileName().toString(), file, relative, content.lines().count(), content);
        Vulnerability llm = new Vulnerability("Potential issue", "HIGH", range, "description", "review");
        llm.setValidationStatus("LOCATION_CHECKED");
        source.setVulnerabilities(new ArrayList<>(List.of(llm)));
        return source;
    }

    private static SemgrepReportService.Report report(String path, int begin, int end) {
        return new SemgrepReportService.Report(List.of(
                new SemgrepReportService.Finding("java.test", path, begin, end, "WARNING", "rule match")), List.of());
    }
}
