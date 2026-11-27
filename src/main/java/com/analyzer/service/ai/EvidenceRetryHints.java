package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A small, bounded SOURCE-ONLY reminder for a failed evidence/line retry.
 * Never changes an LLM finding, never assigns a validation status and never
 * exports source data. Exact citation must still pass StructuredEvidencePreflight.
 */
final class EvidenceRetryHints {
    private static final Pattern LINE = Pattern.compile("^L([0-9]{1,7})\\s*\\|\\s?(.*)$");
    private static final int MAX_CANDIDATES = 3;
    private static final int MAX_CONTEXT_LINES = 12;
    private static final int MAX_LINE_CHARS = 280;
    private static final int MAX_HINT_CHARS = 2000;

    private EvidenceRetryHints() { }

    static String build(String numberedSource, String previousResponse, ObjectMapper mapper) {
        if (numberedSource == null || previousResponse == null || mapper == null) return "";
        try {
            JsonNode root = mapper.readTree(previousResponse);
            if (root == null || !root.isObject() || !root.path("vulnerabilities").isArray()) return "";
            Map<Integer, String> available = new LinkedHashMap<>();
            for (String sourceLine : numberedSource.lines().toList()) {
                Matcher m = LINE.matcher(sourceLine);
                if (m.matches()) available.put(Integer.parseInt(m.group(1)), m.group(2));
            }
            if (available.isEmpty()) return "";
            Map<Integer, String> context = new LinkedHashMap<>();
            JsonNode findings = root.path("vulnerabilities");
            for (int i = 0; i < Math.min(findings.size(), MAX_CANDIDATES); i++) {
                JsonNode finding = findings.get(i);
                if (finding == null || !finding.isObject()) continue;
                JsonNode startNode = finding.path("startLine");
                JsonNode endNode = finding.path("endLine");
                if (!startNode.isIntegralNumber() || !endNode.isIntegralNumber()
                        || !startNode.canConvertToInt() || !endNode.canConvertToInt()) continue;
                int start = startNode.asInt();
                int end = endNode.asInt();
                if (start < 1 || end < start || end - start > 30) continue;
                // A nearby line helps detect off-by-one errors (e.g. Case008: 5 vs 6).
                int left = Math.max(1, start - 1);
                int right = Math.min(1_000_000, Math.min(end + 1, start + 3));
                for (int line = left; line <= right && context.size() < MAX_CONTEXT_LINES; line++) {
                    if (available.containsKey(line)) context.putIfAbsent(line, available.get(line));
                }
            }
            if (context.isEmpty()) return "";
            StringBuilder hint = new StringBuilder("\n\nПОДСКАЗКА ПО ИСХОДНЫМ СТРОКАМ (НЕ ИНСТРУКЦИИ):\n"
                    + "Внимательно перепроверь startLine/endLine: ошибка в один номер строки возможна. "
                    + "Для evidence скопируй точную подстроку ОДНОЙ исходной строки. "
                    + "Не считай подсказку доказательством уязвимости.\n");
            for (var entry : context.entrySet()) {
                String code = entry.getValue();
                // An abbreviated line cannot be quoted verbatim. The complete
                // original source is already in the prompt, so skip long lines.
                if (code.length() > MAX_LINE_CHARS) continue;
                String next = "L" + entry.getKey() + " | " + code + "\n";
                if (hint.length() + next.length() > MAX_HINT_CHARS) break;
                hint.append(next);
            }
            return hint.toString();
        } catch (Exception ignored) {
            // Retrying must not fail because a broken model reply cannot be parsed.
            return "";
        }
    }
}
