package com.analyzer.service.ai;

import com.analyzer.domain.model.Vulnerability;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Verifies literal evidence before returning a model response as a completed scan. */
final class StructuredEvidencePreflight {
    private static final Pattern LINE = Pattern.compile("^L([0-9]{1,7})\\s*\\|\\s?(.*)$");

    private StructuredEvidencePreflight() { }

    static void check(String numberedSource, List<Vulnerability> findings) {
        if (findings.isEmpty()) return;
        Map<Integer, String> source = new HashMap<>();
        for (String line : numberedSource.lines().toList()) {
            Matcher matcher = LINE.matcher(line);
            if (matcher.matches()) source.put(Integer.parseInt(matcher.group(1)), normalize(matcher.group(2)));
        }
        if (source.isEmpty()) throw new IllegalArgumentException("нет исходных строк для проверки цитат");
        for (int i = 0; i < findings.size(); i++) {
            if (!evidenceMatches(source, findings.get(i))) {
                throw new IllegalArgumentException("находка №" + (i + 1)
                        + ": цитата evidence отсутствует на заявленной исходной строке");
            }
        }
    }

    static boolean matches(String numberedSource, Vulnerability finding) {
        return evidenceMatches(sourceMap(numberedSource), finding);
    }

    /** Only an actual one-line model quote may match. Never use blank/null as a match. */
    private static boolean evidenceMatches(Map<Integer, String> source, Vulnerability finding) {
        if (finding.getStartLine() == null || finding.getEndLine() == null) return false;
        String quote = finding.getEvidence();
        if (quote == null || quote.isBlank() || quote.length() < 6 || quote.contains("\n")
                || quote.contains("\r") || quote.contains("...")) return false;
        String normalized = normalize(quote);
        for (int line = finding.getStartLine(); line <= finding.getEndLine(); line++) {
            String actual = source.get(line);
            if (actual != null && actual.contains(normalized)) return true;
        }
        return false;
    }

    static String sourceExcerpt(String numberedSource, int sourceLine) {
        for (String line : numberedSource.lines().toList()) {
            Matcher matcher = LINE.matcher(line);
            if (matcher.matches() && Integer.parseInt(matcher.group(1)) == sourceLine) {
                String excerpt = matcher.group(2);
                return excerpt.length() <= 240 ? excerpt : excerpt.substring(0, 240);
            }
        }
        return null;
    }

    private static Map<Integer, String> sourceMap(String numberedSource) {
        Map<Integer, String> source = new HashMap<>();
        for (String line : numberedSource.lines().toList()) {
            Matcher matcher = LINE.matcher(line);
            if (matcher.matches()) source.put(Integer.parseInt(matcher.group(1)), normalize(matcher.group(2)));
        }
        return source;
    }

    private static String normalize(String text) {
        return text == null ? "" : text.strip().replaceAll("\\s+", " ");
    }
}
