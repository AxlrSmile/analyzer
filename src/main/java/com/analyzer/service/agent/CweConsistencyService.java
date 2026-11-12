package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Lightweight consistency checks, NOT a vulnerability classifier.
 * These tests are intentionally independent from benchmark labels.
 * The status never replaces a SAST finding or a location/evidence check.
 */
public final class CweConsistencyService {
    private CweConsistencyService() { }

    public static void assess(Vulnerability finding) {
        if (finding == null) throw new IllegalArgumentException("finding == null");
        finding.setSemanticStatus("UNKNOWN");
        finding.setSemanticNote("Связь CWE и описания не оценена; требуется экспертная проверка.");
        String title = lower(finding.getTitle());
        String description = lower(finding.getDescription());
        String evidence = lower(finding.getEvidence());
        String actual = finding.getCwe() == null ? "" : finding.getCwe().trim().toUpperCase(Locale.ROOT);
        if (actual.isEmpty()) return;

        String expected = expectedCwe(title);
        if (expected != null && !expected.equals(actual)) {
            finding.setSemanticStatus("CWE_MISMATCH");
            finding.setSemanticNote("Название находки похоже на категорию " + expected
                    + ", но LLM указала " + actual
                    + ". Это сигнал несогласованности, не автоматический диагноз.");
            return;
        }
        // A narrow, explainable mismatch check: evidence citing a URI or an
        // environment variable by itself does not substantiate a SQL sink.
        if ("CWE-89".equals(actual) && (
                evidence.contains("uri.create(") || evidence.contains("system.getenv("))
                && !Pattern.compile("(?i)\\b(select|insert|update|delete|preparestatement|executequery)\\b")
                        .matcher(evidence).find()) {
            finding.setSemanticStatus("CONTEXT_WARNING");
            finding.setSemanticNote("Приведённая цитата не демонстрирует SQL-операцию; "
                    + "для CWE-89 требуется найти путь данных к SQL-запросу.");
            return;
        }
        if ("CWE-502".equals(actual) && (evidence.contains("files.readstring(")
                || evidence.contains("files.readallbytes(") || evidence.contains("readnbytes("))
                && !evidence.contains("readobject(")) {
            finding.setSemanticStatus("CONTEXT_WARNING");
            finding.setSemanticNote("В цитате видно чтение обычного текста или байтов, "
                    + "но нет Java-десериализации объектов. Для CWE-502 проверьте "
                    + "реальное использование ObjectInputStream или другого десериализатора.");
            return;
        }
        if ("CWE-79".equals(actual) && (evidence.contains("encode.forhtml(")
                || evidence.contains("escapehtml("))) {
            finding.setSemanticStatus("CONTEXT_WARNING");
            finding.setSemanticNote("В цитате есть признак HTML-экранирования; "
                    + "проверьте контекст вывода, прежде чем считать находку XSS.");
            return;
        }
        if ("CWE-89".equals(actual) && (evidence.contains("preparedstatement")
                || (evidence.contains("?") && description.contains("parameterized")))) {
            finding.setSemanticStatus("CONTEXT_WARNING");
            finding.setSemanticNote("В цитате есть признаки параметризованного SQL; "
                    + "проверьте окружающий код перед выводом об инъекции.");
            return;
        }
        if (expected != null) {
            finding.setSemanticStatus("CWE_CONSISTENT");
            finding.setSemanticNote("Название и CWE относятся к одной типовой категории. "
                    + "Это не проверка реальной уязвимости или корректности доказательств.");
        }
    }

    /** CWE category suggested by a title alone, never proof of a weakness. */
    public static String titleCategory(String title) {
        return expectedCwe(lower(title));
    }

    private static String expectedCwe(String title) {
        if (has(title, "xxe", "xml external entity", "external xml", "внешних xml")) return "CWE-611";
        if (has(title, "sql injection", "sql-инъек", "sql инъек")) return "CWE-89";
        if (has(title, "cross-site scripting", "xss", "межсайтов")) return "CWE-79";
        if (has(title, "command injection", "shell injection", "инъекци", "внедрени")
                && has(title, "команд", "command", "shell")) return "CWE-78";
        if (has(title, "path traversal", "directory traversal", "обход каталог", "обход пут")) return "CWE-22";
        if (has(title, "deserializ", "десериализ")) return "CWE-502";
        if (has(title, "ssrf", "server-side request forgery")) return "CWE-918";
        if (has(title, "hardcoded secret", "hardcoded api key", "hard-coded api key", "hardcoded credential", "hard-coded credential", "зашитый пароль", "секрет в коде")) return "CWE-798";
        if (has(title, "sensitive information logging", "insecure logging of sensitive", "logging of sensitive", "логирование парол", "пароль в журнал")) return "CWE-532";
        return null;
    }

    private static boolean has(String text, String... terms) {
        for (String term : terms) if (text.contains(term)) return true;
        return false;
    }
    private static String lower(String text) {
        return text == null ? "" : text.toLowerCase(Locale.ROOT);
    }
}
