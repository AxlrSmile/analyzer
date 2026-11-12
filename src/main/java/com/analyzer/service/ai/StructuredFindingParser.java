package com.analyzer.service.ai;

import com.analyzer.domain.model.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Fail-closed parser: malformed LLM output is never treated as a clean scan. */
public final class StructuredFindingParser {
    private static final Pattern CWE = Pattern.compile("CWE-[1-9][0-9]{0,4}");
    private static final Set<String> SEVERITIES = Set.of("HIGH", "MEDIUM", "LOW");
    private static final int MAX_FINDINGS = 50;
    private final ObjectMapper mapper;

    public StructuredFindingParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** Parses independent candidates without interpreting a bad item as a clean scan.
     *  Only evidence may be retained in an unverified state. Invalid structure
     *  drops that individual candidate and is recorded in issues.
     */
    public record ParseOutcome(List<Vulnerability> findings, List<String> issues, int candidateCount) {
        public ParseOutcome {
            findings = List.copyOf(findings);
            issues = List.copyOf(issues);
        }
        public boolean incomplete() { return !issues.isEmpty(); }
    }

    public ParseOutcome parseBestEffort(String text) throws IOException {
        JsonNode nodes = getNodes(text);
        List<Vulnerability> accepted = new ArrayList<>();
        List<String> issues = new ArrayList<>();
        for (int i = 0; i < nodes.size(); i++) {
            try {
                accepted.add(parseOne(nodes.get(i), i, false));
                if ("EVIDENCE_UNVERIFIED".equals(accepted.getLast().getModelOutputStatus())) {
                    issues.add("Находка LLM №" + (i + 1) + ": некорректное evidence");
                }
            } catch (IllegalArgumentException invalid) {
                issues.add(invalid.getMessage());
            }
        }
        return new ParseOutcome(accepted, issues, nodes.size());
    }

    public List<Vulnerability> parse(String text) throws IOException {
        JsonNode nodes = getNodes(text);
        List<Vulnerability> findings = new ArrayList<>();
        for (int i = 0; i < nodes.size(); i++) {
            findings.add(parseOne(nodes.get(i), i, true));
        }
        return List.copyOf(findings);
    }

    private JsonNode getNodes(String text) throws IOException {
        JsonNode root = mapper.readTree(text);
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("Ответ модели должен быть JSON-объектом");
        }
        JsonNode nodes = root.get("vulnerabilities");
        if (nodes == null || !nodes.isArray() || nodes.size() > MAX_FINDINGS) {
            throw new IllegalArgumentException("Ожидается массив vulnerabilities размером до 50");
        }
        return nodes;
    }

    private static Vulnerability parseOne(JsonNode node, int i, boolean strictEvidence) {
        if (!node.isObject()) throw invalid(i, "находка не является объектом");
        String title = required(node, "title", i, 160);
        String severity = required(node, "severity", i, 30).toUpperCase(Locale.ROOT);
        String cwe = required(node, "cwe", i, 20).toUpperCase(Locale.ROOT);
        String description = required(node, "description", i, 2000);
        String recommendation = required(node, "recommendation", i, 2000);
        if (!SEVERITIES.contains(severity)) throw invalid(i, "severity должна быть HIGH/MEDIUM/LOW");
        if (!CWE.matcher(cwe).matches()) throw invalid(i, "некорректный код CWE");
        int start = line(node, "startLine", i);
        int end = line(node, "endLine", i);
        if (end < start || end - start > 30) {
            throw invalid(i, "некорректный или слишком широкий диапазон строк");
        }
        JsonNode evidenceNode = node.get("evidence");
        String evidence = evidenceNode != null && evidenceNode.isTextual()
                ? evidenceNode.asText().trim() : null;
        boolean validEvidence = evidence != null && evidence.length() >= 6
                && evidence.length() <= 400 && !evidence.contains("\n")
                && !evidence.contains("\r") && !evidence.contains("...");
        if (strictEvidence && !validEvidence) {
            throw invalid(i, "evidence должна быть точной однострочной цитатой исходного кода");
        }
        Vulnerability finding = new Vulnerability(title, severity,
                start == end ? Integer.toString(start) : start + "-" + end,
                description, recommendation);
        finding.setStartLine(start);
        finding.setEndLine(end);
        finding.setCwe(cwe);
        finding.setEvidence(evidence != null && evidence.length() <= 400 ? evidence : null);
        if (!validEvidence) {
            finding.setModelOutputStatus("EVIDENCE_UNVERIFIED");
            finding.setModelOutputNote("Модель вернула evidence неверного формата; "
                    + "цитата не считается подтверждённой.");
        }
        return finding;
    }

    private static String required(JsonNode node, String name, int index, int maxLength) {
        JsonNode value = node.get(name);
        if (value == null || !value.isTextual() || value.asText().isBlank()
                || value.asText().length() > maxLength) {
            throw invalid(index, "отсутствует текстовое поле " + name);
        }
        return value.asText().trim();
    }

    private static int line(JsonNode node, String name, int index) {
        JsonNode value = node.get(name);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToInt()) {
            throw invalid(index, name + " должно быть целым числом");
        }
        int number = value.asInt();
        if (number < 1 || number > 1_000_000) throw invalid(index, "номер строки вне диапазона");
        return number;
    }

    private static IllegalArgumentException invalid(int index, String reason) {
        return new IllegalArgumentException("Находка LLM №" + (index + 1) + ": " + reason);
    }
}
