package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Code-based CWE category advisor. Unlike CweConsistencyService, it checks source
 * mechanisms rather than trusting the model's title. No model CWE is overwritten.
 * Source patterns are deliberately narrow and are NOT vulnerability verdicts.
 */
public final class CweSourceAdvisor {
    private static final Pattern SECRET = Pattern.compile(
            "(?i)\\b(?:api[_-]?key|password|passwd|secret|token)\\b[^\\n;]{0,90}=\\s*\\\"[^\\\"\\n]+\\\"");
    private static final Pattern SQL = Pattern.compile(
            "(?is)\\bselect\\s+.{1,160}?\\bfrom\\b|\\binsert\\s+into\\b|\\bupdate\\s+\\w+\\s+set\\b|\\bdelete\\s+from\\b|\\bprepareStatement\\s*\\(");
    private static final Pattern LOG_SENSITIVE = Pattern.compile(
            "(?i)\\b(?:log|logger|logging)\\.(?:info|warn|error|debug|trace)\\s*\\([^\\n]*(?:password|passwd|secret|token)[^\\n]*\\)");
    private static final Pattern COMMAND = Pattern.compile(
            "(?i)\\bProcessBuilder\\s*\\(|\\bRuntime\\.getRuntime\\s*\\(\\s*\\)\\s*\\.exec\\s*\\(");
    private static final Pattern HTML_OUTPUT = Pattern.compile(
            "(?is)\\b(?:return|append|write|print)\\b[^\\n]{0,150}[\\\"']\\s*<\\s*(?:div|span|p|h[1-6]|html|a|script)\\b");
    private static final Pattern PATH = Pattern.compile("(?i)\\bresolve\\s*\\(|\\bnew\\s+File\\s*\\(");

    private CweSourceAdvisor() { }

    public static void assess(CodeChunk chunk, Vulnerability finding) {
        if (chunk == null || finding == null) throw new IllegalArgumentException("Нет исходного кода или находки");
        finding.setCweSuggestion(null);
        finding.setCweAdvisorStatus("REVIEW_REQUIRED");
        finding.setCweAdvisorNote("Категория не подтверждена; требуется ручная проверка.");

        String source = sourceOnly(chunk.prompt());
        String titleCwe = CweConsistencyService.titleCategory(finding.getTitle());
        String sourceCwe = sourceCategory(source);
        String declared = finding.getCwe() == null ? "" : finding.getCwe().trim().toUpperCase(Locale.ROOT);
        boolean verified = finding.hasAbsoluteLineNumbers()
                && "EVIDENCE_MATCHED".equals(finding.getModelOutputStatus())
                || finding.hasAbsoluteLineNumbers()
                && !"EVIDENCE_UNVERIFIED".equals(finding.getModelOutputStatus())
                && !"PARTIAL_RESPONSE".equals(finding.getModelOutputStatus());

        if (sourceCwe != null) {
            finding.setCweSuggestion(sourceCwe);
            if (!verified) {
                set(finding, "SOURCE_HINT_UNVERIFIED_LOCATION",
                        "В исходном фрагменте есть признак категории " + sourceCwe
                        + ", но цитата/строка LLM не подтверждена. Это гипотеза для ручной сверки.");
            } else if (titleCwe != null && !titleCwe.equals(sourceCwe)) {
                set(finding, "SOURCE_TITLE_CONFLICT",
                        "Код указывает на " + sourceCwe + ", а заголовок LLM — на " + titleCwe
                        + ". Не использовать заголовок для автоматического исправления.");
            } else if (!sourceCwe.equals(declared)) {
                set(finding, "SOURCE_CWE_MISMATCH",
                        "Признак в коде соответствует категории " + sourceCwe
                        + ", но модель указала " + declared + ". Предложение не подтверждает уязвимость.");
            } else {
                set(finding, "CATEGORY_ALIGNED",
                        "Код, CWE и заголовок не противоречат друг другу по категории. "
                        + "Это не подтверждение уязвимости.");
            }
            if (containsDefense(source, sourceCwe)) {
                finding.setCweAdvisorNote(finding.getCweAdvisorNote()
                        + " В коде также замечен защитный механизм; возможна ложная тревога.");
            }
            return;
        }
        if ("CWE-89".equals(declared) && !SQL.matcher(source).find()) {
            set(finding, "UNSUPPORTED_SQL_CLAIM",
                    "В исходном фрагменте не обнаружен SQL-механизм для CWE-89. "
                    + "Нельзя подтверждать этот CWE по одному заголовку.");
        } else if (titleCwe != null && !titleCwe.equals(declared)) {
            // Title-only hints are deliberately not exposed as a code-derived CWE.
            set(finding, "TITLE_ONLY_MISMATCH",
                    "Название похоже на " + titleCwe + ", но независимого признака в коде недостаточно. "
                    + "Не заменяем исходный CWE модели.");
        }
    }

    private static String sourceCategory(String source) {
        String lower = source.toLowerCase(Locale.ROOT);
        // Prefer a specific data-flow clue (e.g. password written to a log) over
        // a generic phrase in the model title. Ordered by mechanism specificity.
        if (LOG_SENSITIVE.matcher(source).find()) return "CWE-532";
        if (SECRET.matcher(source).find()) return "CWE-798";
        if (lower.contains("objectinputstream") || lower.contains(".readobject(")) return "CWE-502";
        if (lower.contains("documentbuilderfactory") || lower.contains("saxparserfactory")) return "CWE-611";
        if (SQL.matcher(source).find()) return "CWE-89";
        if (COMMAND.matcher(source).find()) return "CWE-78";
        if (HTML_OUTPUT.matcher(source).find()) return "CWE-79";
        if (PATH.matcher(source).find()) return "CWE-22";
        return null;
    }

    private static boolean containsDefense(String source, String category) {
        String s = source.toLowerCase(Locale.ROOT);
        return switch (category) {
            case "CWE-89" -> s.contains("preparedstatement") && s.contains("?");
            case "CWE-22" -> s.contains("torealpath(") && s.contains("startswith(");
            case "CWE-78" -> s.contains("new processbuilder(")
                    && !s.contains("\"sh\"") && !s.contains("\"cmd\"")
                    && !s.contains("\"powershell\"");
            case "CWE-79" -> s.contains("encode.forhtml(") || s.contains("escapehtml(");
            case "CWE-611" -> s.contains("disallow-doctype-decl")
                    || s.contains("external-general-entities");
            default -> false;
        };
    }

    private static String sourceOnly(String prompt) {
        boolean numbered = prompt.lines().anyMatch(line -> line.matches("^L[0-9]+\\s*\\|.*"));
        StringBuilder code = new StringBuilder();
        for (String line : prompt.lines().toList()) {
            if (!numbered) code.append(line).append('\n');
            else if (line.matches("^L[0-9]+\\s*\\|.*"))
                code.append(line.replaceFirst("^L[0-9]+\\s*\\|\\s?", "")).append('\n');
        }
        return code.toString();
    }

    private static void set(Vulnerability finding, String status, String note) {
        finding.setCweAdvisorStatus(status);
        finding.setCweAdvisorNote(note);
    }
}
