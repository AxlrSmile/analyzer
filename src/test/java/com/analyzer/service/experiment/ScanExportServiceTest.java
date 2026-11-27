package com.analyzer.service.experiment;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.scanner.UnifiedScanService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScanExportServiceTest {
    @TempDir Path dir;
    private final ScanExportService export = new ScanExportService();

    private SourceFile file(String name, boolean withFinding) {
        var file = new SourceFile(name, null, "benchmark-dataset/java/" + name, 8, "class Demo {}");
        if (withFinding) {
            var v = new Vulnerability("SQL Injection", "HIGH", "3", "A string with \"quotes\"", "Review");
            v.setCwe("CWE-89");
            v.setEvidence("String q = \"SELECT\" + user;");
            v.setSemanticStatus("CWE_CONSISTENT");
            v.setMechanismStatus("RELEVANT_PATTERN");
            v.setMechanismNote("Test advisory");
            v.setCweSuggestion("CWE-532");
            v.setCweAdvisorStatus("SOURCE_TITLE_CONFLICT");
            v.setCweAdvisorNote("Test classification");
            v.setValidationStatus("LOCATION_CHECKED");
            v.setStartLine(3); v.setEndLine(3);
            file.setVulnerabilities(new java.util.ArrayList<>(List.of(v)));
        }
        return file;
    }

    @Test void jsonContainsFilesEvenWithoutFindings() throws Exception {
        Path path = dir.resolve("findings.json");
        export.writeJson(path, List.of(file("Case001.java", true), file("Case002.java", false)), null, "local-model");
        var json = new ObjectMapper().readTree(path.toFile());
        assertEquals(2, json.path("files").size());
        assertEquals(1, json.path("findings").size());
        assertEquals("UNKNOWN_OR_MANUAL_IMPORT", json.path("coverage").path("status").asText());
        assertEquals("LLM", json.path("findings").get(0).path("source").asText());
        assertEquals("CWE_CONSISTENT", json.path("findings").get(0).path("semanticStatus").asText());
        assertEquals("RELEVANT_PATTERN", json.path("findings").get(0).path("mechanismStatus").asText());
        assertEquals("CWE-532", json.path("findings").get(0).path("cweSuggestion").asText());
        assertEquals("SOURCE_TITLE_CONFLICT", json.path("findings").get(0).path("cweAdvisorStatus").asText());
    }

    @Test void failedScanIsNotPresentedAsClean() throws Exception {
        var scan = new UnifiedScanService.ScanResult(List.of(file("Case001.java", false)),
                0, 1, false, 0, 0, 0, 0, List.of("LLM не ответила"), 0, 0, 0);
        Path path = dir.resolve("partial.json");
        export.writeJson(path, scan.files(), scan, "local-model");
        var json = new ObjectMapper().readTree(path.toFile());
        assertEquals(1, json.path("coverage").path("llmFailed").asInt());
        assertFalse(json.path("coverage").path("semgrepCompleted").asBoolean());
        assertEquals(0, json.path("findings").size());
    }

    @Test void csvIncludesAllFileRowsAndFindings() throws Exception {
        Path path = dir.resolve("result.csv");
        export.writeCsv(path, List.of(file("Case001.java", true), file("Case002.java", false)));
        String csv = Files.readString(path);
        assertTrue(csv.contains("\"FILE\""));
        assertTrue(csv.contains("\"FINDING\""));
        assertTrue(csv.contains("\"UNKNOWN_OR_MANUAL_IMPORT\""));
        assertTrue(csv.contains("\"CWE-89\""));
        assertTrue(csv.contains("\"mechanismStatus\""));
        assertTrue(csv.contains("\"cweSuggestion\""));
        assertEquals(4, csv.lines().count());
    }

    @Test void csvQuotesAndNeutralizesFormulaCells() {
        assertEquals("\"'=SUM(A1:A3)\"", ScanExportService.csvCell("=SUM(A1:A3)"));
        assertEquals("\"'  +HACK\"", ScanExportService.csvCell("  +HACK"));
        assertEquals("\"say \"\"hello\"\"\"", ScanExportService.csvCell("say \"hello\""));
    }

    @Test void schemaThreeExplicitlyRecordsPartialFilesAndModelEvidence() throws Exception {
        var source = file("Case001.java", true);
        var finding = source.getVulnerabilities().getFirst();
        finding.setModelOutputStatus("EVIDENCE_UNVERIFIED");
        finding.setSourceExcerpt("String x = original;");
        var scan = new UnifiedScanService.ScanResult(List.of(source), 0, 0, true,
                0, 0, 0, 0, List.of("LLM частично проверила Case001.java"),
                0, 0, 0, 1, List.of("benchmark-dataset/java/Case001.java"), List.of());
        Path jsonFile = dir.resolve("partial.json");
        export.writeJson(jsonFile, scan.files(), scan, "local-model");
        var json = new ObjectMapper().readTree(jsonFile.toFile());
        assertEquals(3, json.path("schemaVersion").asInt());
        assertEquals(1, json.path("coverage").path("llmPartial").asInt());
        assertEquals("PARTIAL", json.path("files").get(0).path("llmStatus").asText());
        assertEquals("EVIDENCE_UNVERIFIED", json.path("findings").get(0).path("modelOutputStatus").asText());
        assertEquals("String x = original;", json.path("findings").get(0).path("sourceExcerpt").asText());
        Path csvFile = dir.resolve("partial.csv");
        export.writeCsv(csvFile, scan.files(), scan);
        String csv = Files.readString(csvFile);
        assertTrue(csv.contains("\"PARTIAL\""));
        assertTrue(csv.contains("\"EVIDENCE_UNVERIFIED\""));
    }

    @Test void jsonKeepsSastFindingsDistinctFromLlmFindings() throws Exception {
        var file = file("Case001.java", true);
        var sast = new Vulnerability("Semgrep: rule.id", "HIGH", "4", "SAST", "Review");
        sast.setValidationStatus("SAST_REPORTED");
        file.getVulnerabilities().add(sast);
        Path path = dir.resolve("findings.json");
        export.writeJson(path, List.of(file), null, "local-model");
        var findings = new ObjectMapper().readTree(path.toFile()).path("findings");
        assertEquals(2, findings.size());
        assertEquals("SEMGREP", findings.get(1).path("source").asText());
    }
}
