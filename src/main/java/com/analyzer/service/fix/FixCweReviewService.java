package com.analyzer.service.fix;

import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * Conservative, non-executing heuristics for a few common security mechanisms.
 * This is NEVER a functional proof or a vulnerability verdict. Unrecognized code must remain unverified.
 */
@Service
public class FixCweReviewService {
    public enum Status { PATTERN_PRESENT, REVIEW_REQUIRED, NOT_CHECKED }

    public record Review(Status status, String explanation) {
        public Review {
            if (status == null || explanation == null) throw new IllegalArgumentException("Invalid review");
        }
    }

    public Review inspect(String cwe, String proposalText) {
        if (proposalText == null || proposalText.isBlank()) {
            return new Review(Status.NOT_CHECKED, "Предложенный код отсутствует.");
        }
        String code = proposalText.toLowerCase(Locale.ROOT);
        return switch (cwe == null ? "" : cwe.trim().toUpperCase(Locale.ROOT)) {
            case "CWE-22" -> {
                if (code.contains(".normalize()") && !code.contains(".torealpath(")) {
                    yield new Review(Status.REVIEW_REQUIRED,
                            "Проверяется нормализованный, но не реальный путь: символьные ссылки могут вести за пределы каталога. "
                            + "Нужны проверки обычного пути, ../, ссылки и гонок файловой системы.");
                }
                if (code.contains(".torealpath(") && code.contains(".startswith(")) {
                    yield new Review(Status.PATTERN_PRESENT,
                            "Найдены toRealPath и startsWith. Проверьте связь проверенного пути с чтением файла, "
                            + "символьные ссылки и гонки (TOCTOU). Это не гарантия исправления CWE-22.");
                }
                yield new Review(Status.REVIEW_REQUIRED,
                        "Защитная проверка реального пути не распознана. Нужны функциональные тесты обхода путей.");
            }
            case "CWE-89" -> {
                if (code.contains("preparestatement(") && code.contains("?")
                        && (code.contains(".setstring(") || code.contains(".setint(")
                            || code.contains(".setobject(") || code.contains(".setlong("))) {
                    yield new Review(Status.PATTERN_PRESENT,
                            "Найдены параметризованный SQL и установка параметров. Проверьте, что все вводимые значения "
                            + "переданы как параметры, а не вставлены в SQL. Это не подтверждение безопасности.");
                }
                yield new Review(Status.REVIEW_REQUIRED,
                        "Полный шаблон параметризации SQL не распознан. Проверьте построение SQL и тест с необычным вводом.");
            }
            case "CWE-78" -> new Review(Status.REVIEW_REQUIRED,
                    "Проверьте, что ввод не передаётся в shell и не становится управляющим аргументом команды.");
            case "CWE-79" -> new Review(Status.REVIEW_REQUIRED,
                    "Проверьте контекстно-зависимое HTML-экранирование, включая кавычки и специальные символы.");
            case "CWE-918" -> new Review(Status.REVIEW_REQUIRED,
                    "Проверьте допустимые назначения, DNS/redirect и защиту от внутренних адресов.");
            case "CWE-611" -> new Review(Status.REVIEW_REQUIRED,
                    "Проверьте явный запрет внешних сущностей и DTD в настройках XML-парсера.");
            case "CWE-502" -> new Review(Status.REVIEW_REQUIRED,
                    "Проверьте политику допустимых типов и отказ от небезопасной десериализации.");
            default -> new Review(Status.NOT_CHECKED,
                    "Специальная эвристика для этой категории отсутствует; результат требует ручной проверки.");
        };
    }
}
