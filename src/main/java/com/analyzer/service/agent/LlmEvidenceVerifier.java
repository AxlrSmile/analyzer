package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Checks whether the claimed exact code excerpt occurs on the claimed original source line. */
final class LlmEvidenceVerifier {
    private static final Pattern NUMBERED_SOURCE = Pattern.compile("^L([0-9]{1,7})\\s*\\|\\s?(.*)$");

    private LlmEvidenceVerifier() { }

    static boolean isStructured(Vulnerability finding) {
        return finding.getStartLine() != null || finding.getEndLine() != null
                || finding.getCwe() != null || finding.getEvidence() != null;
    }

    static String check(CodeChunk chunk, Vulnerability finding) {
        Integer start = finding.getStartLine();
        Integer end = finding.getEndLine();
        if (start == null || end == null || start < chunk.startLine()
                || end > chunk.endLine() || end < start) {
            return "Числовые строки LLM вне исходного диапазона фрагмента "
                    + chunk.startLine() + "-" + chunk.endLine();
        }
        String rawEvidence = finding.getEvidence();
        if (rawEvidence == null || rawEvidence.isBlank() || rawEvidence.contains("\n")
                || rawEvidence.contains("\r") || rawEvidence.contains("...")) {
            return "LLM не привела точную однострочную цитату доказательства";
        }
        String evidence = normalize(rawEvidence);
        if (evidence.length() < 6) return "Слишком короткая цитата evidence";

        Map<Integer, String> source = sourceLines(chunk);
        for (int line = start; line <= end; line++) {
            String text = source.get(line);
            if (text != null && normalize(text).contains(evidence)) {
                return null; // Localized evidence, NOT confirmed vulnerability.
            }
        }
        return "Цитата evidence не найдена на указанных строках оригинального кода";
    }

    private static Map<Integer, String> sourceLines(CodeChunk chunk) {
        List<String> lines = chunk.prompt().lines().toList();
        Map<Integer, String> source = new HashMap<>();
        boolean numbered = false;
        for (String line : lines) {
            Matcher matcher = NUMBERED_SOURCE.matcher(line);
            if (matcher.matches()) {
                numbered = true;
                int number = Integer.parseInt(matcher.group(1));
                if (number >= chunk.startLine() && number <= chunk.endLine()) {
                    source.put(number, matcher.group(2));
                }
            }
        }
        if (!numbered) {
            for (int i = 0; i < lines.size() && i < chunk.sourceLineCount(); i++) {
                source.put(chunk.startLine() + i, lines.get(i));
            }
        }
        return source;
    }

    private static String normalize(String text) {
        return text.strip().replaceAll("\\s+", " ");
    }
}
