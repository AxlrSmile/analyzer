package com.analyzer.service.sast;

import com.analyzer.domain.model.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Imports a local JSON report produced by "semgrep scan --json".
 * Does NOT execute Semgrep, validate source code or prove that a finding is exploitable.
 */
@Service
public class SemgrepReportService {
    private static final long MAX_REPORT_BYTES = 20_000_000;
    private final ObjectMapper mapper = new ObjectMapper();

    public record Finding(String ruleId, String path, int startLine, int endLine,
                          String severity, String message) { }

    public record Report(List<Finding> findings, List<String> errors) {
        public Report {
            findings = List.copyOf(findings);
            errors = List.copyOf(errors);
        }
        public boolean hasErrors() { return !errors.isEmpty(); }
    }

    public Report read(Path jsonReport) throws IOException {
        if (jsonReport == null || !Files.isRegularFile(jsonReport)) {
            throw new IOException("JSON-отчёт Semgrep не найден");
        }
        if (Files.size(jsonReport) > MAX_REPORT_BYTES) {
            throw new IOException("Отчёт превышает 20 МБ: проверьте источник файла");
        }
        JsonNode root;
        try (var input = Files.newInputStream(jsonReport)) {
            root = mapper.readTree(input);
        }
        if (root == null || !root.isObject() || !root.path("results").isArray()) {
            throw new IOException("Некорректный Semgrep JSON: отсутствует массив results");
        }
        JsonNode errorNodes = root.path("errors");
        if (!errorNodes.isMissingNode() && !errorNodes.isArray()) {
            throw new IOException("Некорректный Semgrep JSON: errors должен быть массивом");
        }
        List<String> errors = new ArrayList<>();
        if (errorNodes.isArray()) {
            for (JsonNode error : errorNodes) {
                errors.add(error.path("message").asText(error.toString()));
            }
        }
        List<Finding> findings = new ArrayList<>();
        for (JsonNode item : root.get("results")) {
            if (!item.isObject()) {
                throw new IOException("Некорректный Semgrep JSON: элемент results не объект");
            }
            String ruleId = requiredText(item, "check_id");
            String path = requiredText(item, "path");
            JsonNode start = item.path("start");
            JsonNode end = item.path("end");
            JsonNode extra = item.path("extra");
            int first = start.path("line").asInt(0);
            int last = end.path("line").asInt(0);
            if (first < 1 || last < first || !extra.isObject()) {
                throw new IOException("Некорректные координаты или extra в результате Semgrep");
            }
            String severity = requiredText(extra, "severity");
            String message = requiredText(extra, "message");
            findings.add(new Finding(ruleId, path, first, last, severity, message));
        }
        return new Report(findings, errors);
    }

    /** Only resolve relative paths that stay within the selected project directory. */
    public Path resolveInProject(Path projectRoot, String resultPath) throws IOException {
        if (projectRoot == null || resultPath == null || resultPath.isBlank()) {
            throw new IOException("Отсутствует путь к исходному файлу");
        }
        String normalized = resultPath.replace('\\', '/');
        // Reject Windows drive paths even when this code is tested on Unix.
        if (normalized.startsWith("/") || normalized.startsWith("//")
                || normalized.matches("(?i)^[a-z]:.*")) {
            throw new IOException("Путь Semgrep должен быть относительным: " + resultPath);
        }
        Path realRoot = projectRoot.toRealPath();
        Path candidate = realRoot.resolve(normalized).normalize();
        if (!candidate.startsWith(realRoot) || !Files.isRegularFile(candidate)
                || !candidate.toRealPath().startsWith(realRoot)) {
            throw new IOException("Файл отсутствует или находится вне проекта: " + resultPath);
        }
        return candidate.toRealPath();
    }

    public Vulnerability toVulnerability(Finding finding) {
        if (finding == null) throw new IllegalArgumentException("finding == null");
        // Semgrep and the LLM use different severity scales; map for display only.
        String severity = switch (finding.severity().toUpperCase(Locale.ROOT)) {
            case "ERROR", "CRITICAL", "HIGH" -> "HIGH";
            case "WARNING", "MEDIUM" -> "MEDIUM";
            default -> "LOW";
        };
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setTitle("Semgrep: " + finding.ruleId());
        vulnerability.setSeverity(severity);
        vulnerability.setLineRange(finding.startLine() == finding.endLine()
                ? String.valueOf(finding.startLine())
                : finding.startLine() + "-" + finding.endLine());
        vulnerability.setDescription(finding.message());
        vulnerability.setRecommendation("Изучите правило Semgrep и проверьте находку вручную.");
        vulnerability.setValidationStatus("SAST_REPORTED");
        vulnerability.setValidationNote("Срабатывание правила Semgrep (" + finding.ruleId() + ", severity="
                + finding.severity() + "). Это не экспертное подтверждение уязвимости. "
                + "Номера строк относятся ко всему исходному файлу.");
        return vulnerability;
    }

    private static String requiredText(JsonNode node, String key) throws IOException {
        JsonNode value = node.path(key);
        if (!value.isTextual() || value.asText().isBlank()) {
            throw new IOException("Некорректный Semgrep JSON: отсутствует поле " + key);
        }
        return value.asText();
    }
}
