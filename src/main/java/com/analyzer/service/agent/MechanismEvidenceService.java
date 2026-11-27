package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Narrow and explainable source-code signals. NOT a vulnerability oracle.
 * Evaluates a claim against source context, never uses benchmark ground truth.
 * No finding is removed, and no verdict is automatically confirmed.
 */
public final class MechanismEvidenceService {
    private static final Pattern SQL = Pattern.compile(
            "(?is)\\bselect\\s+.{1,120}?\\bfrom\\b|\\binsert\\s+into\\b|\\bupdate\\s+\\w+\\s+set\\b|\\bdelete\\s+from\\b|"
            + "\\bprepareStatement\\s*\\(|\\bexecute(Query|Update)?\\s*\\(");
    private static final Pattern COMMAND = Pattern.compile(
            "(?i)\\bProcessBuilder\\s*\\(|\\bRuntime\\.getRuntime\\s*\\(|\\bexec\\s*\\(");
    private static final Pattern LOG = Pattern.compile(
            "(?i)\\b(log|logger|logging)\\.(info|warn|error|debug|trace)\\s*\\(|System\\.out\\.print");
    private static final Pattern SECRET = Pattern.compile(
            "(?i)\\b(api[_-]?key|password|passwd|secret|token)\\b[^;\\n]{0,65}=\\s*\"[^\"]+\"");

    private MechanismEvidenceService() { }

    public static void assess(CodeChunk chunk, Vulnerability finding) {
        if (chunk == null || finding == null) throw new IllegalArgumentException("Нет кода или находки");
        if (!finding.hasAbsoluteLineNumbers()) {
            set(finding, "UNVERIFIED_LOCATION", "Цитата или абсолютные строки не подтверждены. "
                    + "Семантическую оценку нельзя считать надёжной.");
            return;
        }
        String code = sourceOnly(chunk.prompt());
        String lower = code.toLowerCase(Locale.ROOT);
        String evidence = lower(finding.getEvidence());
        String cwe = finding.getCwe() == null ? "" : finding.getCwe().trim().toUpperCase(Locale.ROOT);
        switch (cwe) {
            case "CWE-89" -> {
                if (!SQL.matcher(code).find()) {
                    set(finding, "MISSING_MECHANISM", "Не найден SQL-запрос или SQL API в данном фрагменте. "
                            + "Нельзя обосновать заявленную SQL-инъекцию этой цитатой.");
                } else if (lower.contains("preparedstatement") && lower.contains("?")
                        && !code.contains("\" +") && !code.contains("+ user")) {
                    set(finding, "DEFENSE_PRESENT", "Найден параметризованный SQL через PreparedStatement. "
                            + "Проверить весь поток данных и другие запросы вручную.");
                } else {
                    set(finding, "RELEVANT_PATTERN", "Виден SQL-контекст; недоверенный источник, "
                            + "путь данных и безопасность исполнения не подтверждены.");
                }
            }
            case "CWE-78" -> {
                if (!COMMAND.matcher(code).find()) {
                    set(finding, "MISSING_MECHANISM", "В фрагменте не найден запуск внешних процессов.");
                } else if (!lower.contains("\"sh\"") && !lower.contains("\"cmd\"")
                        && !lower.contains("\"powershell\"") && evidence.contains("processbuilder(")) {
                    set(finding, "DEFENSE_PRESENT", "ProcessBuilder получает отдельные аргументы "
                            + "без очевидного вызова shell -c; проверьте входные данные и исполняемый путь.");
                } else {
                    set(finding, "RELEVANT_PATTERN", "Есть вызов внешнего процесса; проверьте "
                            + "достижимость недоверенного ввода и наличие командной оболочки.");
                }
            }
            case "CWE-22" -> {
                if (!lower.contains("resolve(") && !lower.contains("getpath(")
                        && !lower.contains("new file(")) {
                    set(finding, "MISSING_MECHANISM", "В видимом контексте не найдено "
                            + "построение пути из параметров.");
                } else if (lower.contains("torealpath(") && lower.contains("startswith(")) {
                    set(finding, "DEFENSE_PRESENT", "Найдены канонизация пути и проверка его границ. "
                            + "Нужно проверить порядок проверок и дальнейшее использование пути.");
                } else {
                    set(finding, "RELEVANT_PATTERN", "Обрабатываются пути; проверьте ограничение "
                            + "доступа за пределами разрешённой директории.");
                }
            }
            case "CWE-502" -> {
                if (!lower.contains("readobject(") && !lower.contains("objectinputstream")) {
                    set(finding, "MISSING_MECHANISM", "Не найдено чтение Java-объекта; "
                            + "обычное Files.readString само по себе не Java-десериализация.");
                } else {
                    set(finding, "RELEVANT_PATTERN", "Используется десериализация объектов; "
                            + "источник и фильтры входных данных требуют проверки.");
                }
            }
            case "CWE-79" -> {
                if (lower.contains("encode.forhtml(") || lower.contains("escapehtml(")) {
                    set(finding, "DEFENSE_PRESENT", "Обнаружено HTML-экранирование. "
                            + "Нужна проверка конкретного контекста вывода.");
                } else if (lower.contains("<html") || lower.contains("<div")
                        || lower.contains("<span") || lower.contains("innerhtml")) {
                    set(finding, "RELEVANT_PATTERN", "Есть HTML-контекст; "
                            + "источник текста и его кодирование не проверены.");
                } else {
                    set(finding, "REVIEW_REQUIRED", "По данному фрагменту недостаточно данных "
                            + "о способе вывода в HTML.");
                }
            }
            case "CWE-611" -> {
                if (!lower.contains("documentbuilderfactory") && !lower.contains("saxparserfactory")) {
                    set(finding, "MISSING_MECHANISM", "В фрагменте нет соответствующего XML-парсера.");
                } else if (lower.contains("disallow-doctype-decl")
                        || lower.contains("external-general-entities")) {
                    set(finding, "DEFENSE_PRESENT", "Есть конфигурация ограничений XML-сущностей. "
                            + "Проверьте применимость всех настроек.");
                } else {
                    set(finding, "RELEVANT_PATTERN", "Есть XML-парсер; "
                            + "политика обработки внешних сущностей требует проверки.");
                }
            }
            case "CWE-532" -> {
                if (LOG.matcher(code).find() && lower.contains("password")) {
                    set(finding, "RELEVANT_PATTERN", "Пароль упоминается в контексте журналирования; "
                            + "проверьте, выводится ли само значение.");
                } else {
                    set(finding, "REVIEW_REQUIRED", "Прямая связь секрета с записью в журнал не установлена.");
                }
            }
            case "CWE-798" -> {
                if (SECRET.matcher(code).find()) {
                    set(finding, "RELEVANT_PATTERN", "Есть литерал, похожий на учётный секрет. "
                            + "Синтетическое значение не обязательно является настоящим ключом.");
                } else if (lower.contains("system.getenv(")) {
                    set(finding, "DEFENSE_PRESENT", "Значение читается из окружения, "
                            + "а не из видимого строкового литерала; проверьте дальнейшую обработку.");
                } else {
                    set(finding, "REVIEW_REQUIRED", "Не найдено явного присваивания секретного литерала.");
                }
            }
            case "CWE-338" -> {
                if (lower.contains("securerandom")) {
                    set(finding, "DEFENSE_PRESENT", "Есть SecureRandom; нужно проверить, "
                            + "как формируется и используется токен.");
                } else if (lower.contains("new random(")) {
                    set(finding, "RELEVANT_PATTERN", "Есть Random; проверьте применение "
                            + "к чувствительным токенам.");
                } else {
                    set(finding, "REVIEW_REQUIRED", "Неясен источник случайности.");
                }
            }
            default -> set(finding, "REVIEW_REQUIRED", "Для этой CWE нет узкого "
                    + "детерминированного правила; требуется контекстная проверка.");
        }
    }

    private static void set(Vulnerability v, String status, String note) {
        v.setMechanismStatus(status);
        v.setMechanismNote(note);
    }

    private static String sourceOnly(String prompt) {
        StringBuilder source = new StringBuilder();
        boolean numbered = prompt.lines().anyMatch(line -> line.matches("^L[0-9]+\\s*\\|.*"));
        for (String line : prompt.lines().toList()) {
            if (!numbered) source.append(line).append('\n');
            else if (line.matches("^L[0-9]+\\s*\\|.*"))
                source.append(line.replaceFirst("^L[0-9]+\\s*\\|\\s?", "")).append('\n');
        }
        return source.toString();
    }

    private static String lower(String text) {
        return text == null ? "" : text.toLowerCase(Locale.ROOT);
    }
}
