package com.analyzer.service.experiment;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.scanner.UnifiedScanService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Reproducible raw observations. Does not use ground_truth or fabricate metrics. */
@Service
public class ScanExportService {
    private static final String[] CSV_HEADERS = {
            "recordType", "scanStatus", "llmStatus", "file", "source", "title", "severity", "cwe", "semanticStatus", "semanticNote",
            "mechanismStatus", "mechanismNote", "cweSuggestion", "cweAdvisorStatus", "cweAdvisorNote", "startLine", "endLine", "lineRange", "locationStatus", "locationNote",
            "absoluteLineNumbers", "evidence", "sourceExcerpt", "modelOutputStatus", "modelOutputNote", "description", "recommendation",
            "aiReviewStatus", "aiReviewNote"
    };
    private final ObjectMapper mapper;

    public ScanExportService(ObjectMapper mapper) { this.mapper = mapper; }
    public ScanExportService() { this(new ObjectMapper()); }

    public void writeJson(Path destination, List<SourceFile> files,
                          UnifiedScanService.ScanResult scan, String model) throws IOException {
        var root = new LinkedHashMap<String, Object>();
        root.put("schemaVersion", 3);
        root.put("exportedAtUtc", Instant.now().toString());
        root.put("model", model);
        root.put("evaluationUnit", "finding");
        root.put("warning", "Предварительные находки. Строки и CWE не доказывают уязвимость. "
                + "Сбой анализа нельзя считать отсутствием находок. Экспорт может содержать исходный код и секреты.");
        root.put("coverage", coverage(scan));
        var fileRows = new ArrayList<Map<String, Object>>();
        for (SourceFile file : files) {
            var row = new LinkedHashMap<String, Object>();
            row.put("file", fileName(file));
            row.put("findingCount", file.getVulnerabilities().size());
            row.put("llmStatus", llmStatus(scan, file));
            fileRows.add(row);
        }
        root.put("files", fileRows);
        root.put("findings", rows(files));
        Files.writeString(destination, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                StandardCharsets.UTF_8);
    }

    public void writeCsv(Path destination, List<SourceFile> files) throws IOException {
        writeCsv(destination, files, null);
    }

    public void writeCsv(Path destination, List<SourceFile> files,
                         UnifiedScanService.ScanResult scan) throws IOException {
        StringBuilder csv = new StringBuilder();
        for (int i = 0; i < CSV_HEADERS.length; i++) {
            if (i > 0) csv.append(',');
            csv.append(csvCell(CSV_HEADERS[i]));
        }
        csv.append("\r\n");
        String scanStatus = scan == null ? "UNKNOWN_OR_MANUAL_IMPORT"
                : (scan.sastCompleted() && scan.failedByLlm() == 0 && scan.partialByLlm() == 0
                        && scan.skippedTargets() == 0 && scan.diagnostics().isEmpty()
                        ? "COMPLETE" : "PARTIAL_OR_DIAGNOSTICS");
        // One FILE record per selected source, even without findings, so an
        // evaluator can distinguish an observed zero from a missing file.
        for (SourceFile file : files) {
            var record = new LinkedHashMap<String, Object>();
            record.put("recordType", "FILE");
            record.put("scanStatus", scanStatus);
            record.put("file", fileName(file));
            record.put("llmStatus", llmStatus(scan, file));
            csvRow(csv, record);
        }
        for (Map<String, Object> finding : rows(files)) {
            var record = new LinkedHashMap<>(finding);
            record.put("recordType", "FINDING");
            record.put("scanStatus", scanStatus);
            record.put("llmStatus", llmStatusForPath(scan, (String) finding.get("file")));
            csvRow(csv, record);
        }
        Files.writeString(destination, csv.toString(), StandardCharsets.UTF_8);
    }

    private static void csvRow(StringBuilder csv, Map<String, Object> record) {
        for (int i = 0; i < CSV_HEADERS.length; i++) {
            if (i > 0) csv.append(',');
            csv.append(csvCell(record.get(CSV_HEADERS[i])));
        }
        csv.append("\r\n");
    }

    /** Exposed for deterministic tests; untrusted text must not become a spreadsheet formula. */
    public static String csvCell(Object raw) {
        String text = raw == null ? "" : raw.toString().replace("\u0000", "");
        String leading = text.stripLeading();
        if (!leading.isEmpty() && "=+-@".indexOf(leading.charAt(0)) >= 0) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private static Map<String, Object> coverage(UnifiedScanService.ScanResult scan) {
        var coverage = new LinkedHashMap<String, Object>();
        if (scan == null) {
            coverage.put("status", "UNKNOWN_OR_MANUAL_IMPORT");
        } else {
            coverage.put("status", "RECORDED");
            coverage.put("llmSucceeded", scan.analyzedByLlm());
            coverage.put("llmFailed", scan.failedByLlm());
            coverage.put("llmPartial", scan.partialByLlm());
            coverage.put("llmPartialFiles", scan.partialFiles());
            coverage.put("llmFailedFiles", scan.failedFiles());
            coverage.put("semgrepCompleted", scan.sastCompleted());
            coverage.put("semgrepFindings", scan.sastFindings());
            coverage.put("skippedTargets", scan.skippedTargets());
            coverage.put("aiReviewed", scan.aiReviewed());
            coverage.put("aiReviewFailed", scan.aiReviewFailed());
            coverage.put("aiReviewSkipped", scan.aiReviewSkipped());
            coverage.put("diagnostics", scan.diagnostics());
        }
        return coverage;
    }

    private static List<Map<String, Object>> rows(List<SourceFile> files) {
        var rows = new ArrayList<Map<String, Object>>();
        for (SourceFile file : files) {
            for (Vulnerability v : file.getVulnerabilities()) {
                var row = new LinkedHashMap<String, Object>();
                row.put("file", fileName(file));
                row.put("source", "SAST_REPORTED".equals(v.getValidationStatus()) ? "SEMGREP" : "LLM");
                row.put("title", v.getTitle());
                row.put("severity", v.getSeverity());
                row.put("cwe", v.getCwe());
                row.put("semanticStatus", v.getSemanticStatus());
                row.put("semanticNote", v.getSemanticNote());
                row.put("mechanismStatus", v.getMechanismStatus());
                row.put("mechanismNote", v.getMechanismNote());
                row.put("cweSuggestion", v.getCweSuggestion());
                row.put("cweAdvisorStatus", v.getCweAdvisorStatus());
                row.put("cweAdvisorNote", v.getCweAdvisorNote());
                row.put("startLine", v.getStartLine());
                row.put("endLine", v.getEndLine());
                row.put("lineRange", v.getLineRange());
                row.put("locationStatus", v.getValidationStatus());
                row.put("locationNote", v.getValidationNote());
                row.put("absoluteLineNumbers", v.hasAbsoluteLineNumbers());
                row.put("evidence", v.getEvidence());
                row.put("sourceExcerpt", v.getSourceExcerpt());
                row.put("modelOutputStatus", v.getModelOutputStatus());
                row.put("modelOutputNote", v.getModelOutputNote());
                row.put("description", v.getDescription());
                row.put("recommendation", v.getRecommendation());
                row.put("aiReviewStatus", v.getAiReviewStatus());
                row.put("aiReviewNote", v.getAiReviewNote());
                rows.add(row);
            }
        }
        return rows;
    }

    private static String llmStatus(UnifiedScanService.ScanResult scan, SourceFile file) {
        return llmStatusForPath(scan, fileName(file));
    }

    private static String llmStatusForPath(UnifiedScanService.ScanResult scan, String file) {
        if (scan == null) return "UNKNOWN";
        if (scan.failedFiles().contains(file)) return "FAILED";
        if (scan.partialFiles().contains(file)) return "PARTIAL";
        return "COMPLETE";
    }

    private static String fileName(SourceFile file) {
        String path = file.getRelativePath();
        if (path == null || path.isBlank()) return file.getName() == null ? "unknown" : file.getName();
        return path.replace('\\', '/');
    }
}
