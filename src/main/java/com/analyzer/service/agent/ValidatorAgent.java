package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Второй этап аудита: детерминированная проверка локализации LLM-находок.
 * Не подтверждает наличие уязвимости и не удаляет подозрительные находки.
 * Для located-фрагментов проверяет АБСОЛЮТНЫЕ номера строк исходного файла.
 */
@Service
public class ValidatorAgent {

    private static final Pattern LINE_RANGE = Pattern.compile(
            "(?i)^\\s*L?(\\d{1,7})(?:\\s*[-–—]\\s*L?(\\d{1,7}))?\\s*$");

    public List<Vulnerability> validateChunk(String codeChunk, List<Vulnerability> findings) {
        if (findings == null) {
            throw new IllegalArgumentException("Невозможно проверить null вместо списка находок");
        }
        if (findings.isEmpty()) return List.of();
        if (codeChunk == null || codeChunk.isBlank()) {
            throw new IllegalArgumentException("Для проверки находок необходим исходный код");
        }

        long lineCount = codeChunk.lines().count();
        if (lineCount > 0 && lineCount <= Integer.MAX_VALUE
                && findings.stream().anyMatch(LlmEvidenceVerifier::isStructured)) {
            return validateLocatedChunk(new CodeChunk(codeChunk, 1, (int) lineCount), findings);
        }
        Set<String> seen = new HashSet<>();

        for (Vulnerability finding : findings) {
            if (finding == null) {
                throw new IllegalArgumentException("В списке находок присутствует null");
            }

            finding.setAbsoluteLineNumbers(false);
            String range = finding.getLineRange();
            if (range == null || range.isBlank()) {
                mark(finding, "NEEDS_REVIEW",
                        "LLM не указала строки. Требуется ручная локализация и проверка находки.");
                continue;
            }
            Matcher match = LINE_RANGE.matcher(range);
            if (!match.matches()) {
                mark(finding, "NEEDS_REVIEW",
                        "Непонятный диапазон строк: " + range + ". Проверьте вручную.");
                continue;
            }

            long start = Long.parseLong(match.group(1));
            long end = match.group(2) == null ? start : Long.parseLong(match.group(2));
            if (start < 1 || end < start || end > lineCount) {
                mark(finding, "NEEDS_REVIEW", "Строки " + range
                        + " выходят за границы фрагмента (1–" + lineCount + ").");
                continue;
            }

            // Нормализуем только координаты фрагмента. Сдвиг относительно файла
            // пока неизвестен и не должен выдаваться за точную линию в проекте.
            String canonical = start == end ? Long.toString(start) : start + "-" + end;
            finding.setLineRange(canonical);
            String signature = normalize(finding.getTitle()) + "|" + canonical
                    + "|" + normalize(finding.getDescription());

            if (!seen.add(signature)) {
                mark(finding, "POSSIBLE_DUPLICATE",
                        "Похожая находка уже встречалась в этом фрагменте. Нужна проверка.");
            } else {
                mark(finding, "LOCATION_CHECKED",
                        "Указанные строки существуют внутри фрагмента. "
                        + "Это НЕ подтверждение уязвимости; номера относительно фрагмента.");
            }
        }
        return List.copyOf(findings);
    }

    /**
     * Validates model-produced coordinates against ORIGINAL-file bounds.
     * A prompt header (or L-number prefix) is never counted as source code.
     * The model is instructed to return absolute L-numbers for long chunks.
     * Unambiguously local numbers can be shifted for display, but are marked
     * INFERRED and must NOT be automatically correlated with SAST findings.
     */
    public List<Vulnerability> validateLocatedChunk(CodeChunk chunk, List<Vulnerability> findings) {
        if (chunk == null) throw new IllegalArgumentException("Не переданы координаты фрагмента");
        if (findings == null) throw new IllegalArgumentException("Список находок равен null");
        if (findings.isEmpty()) return List.of();
        Set<String> seen = new HashSet<>();

        for (Vulnerability finding : findings) {
            if (finding == null) throw new IllegalArgumentException("В списке находок присутствует null");
            finding.setAbsoluteLineNumbers(false);
            if (LlmEvidenceVerifier.isStructured(finding)) {
                CweConsistencyService.assess(finding);
                Integer startLine = finding.getStartLine();
                Integer endLine = finding.getEndLine();
                // Never guess an offset or trust a line number based only on its existence.
                if (startLine != null && endLine != null && startLine > 0 && endLine >= startLine) {
                    finding.setLineRange(canonical(startLine, endLine));
                }
                String reason = LlmEvidenceVerifier.check(chunk, finding);
                if (reason != null) {
                    mark(finding, "NEEDS_REVIEW", reason + "; координаты/уязвимость не подтверждены.");
                } else {
                    finding.setAbsoluteLineNumbers(true);
                    if (!seen.add(signature(finding))) {
                        mark(finding, "POSSIBLE_DUPLICATE", "Повтор структурированной находки в фрагменте");
                    } else {
                        mark(finding, "LOCATION_CHECKED",
                                "Строки и точная цитата кода сверены с оригиналом; "
                                + "это НЕ подтверждает эксплуатационную уязвимость.");
                    }
                }
                MechanismEvidenceService.assess(chunk, finding);
                CweSourceAdvisor.assess(chunk, finding);
                continue;
            }
            String raw = finding.getLineRange();
            if (raw == null || raw.isBlank()) {
                mark(finding, "NEEDS_REVIEW", "LLM не указала строки исходного файла.");
                continue;
            }
            Matcher match = LINE_RANGE.matcher(raw);
            if (!match.matches()) {
                mark(finding, "NEEDS_REVIEW", "Не удалось разобрать диапазон исходных строк: " + raw);
                continue;
            }
            long start = Long.parseLong(match.group(1));
            long end = match.group(2) == null ? start : Long.parseLong(match.group(2));
            if (start < 1 || end < start) {
                mark(finding, "NEEDS_REVIEW", "Неверный порядок или номер строк: " + raw);
                continue;
            }

            boolean absolute = start >= chunk.startLine() && end <= chunk.endLine();
            boolean relative = start >= 1 && end <= chunk.sourceLineCount();
            if (absolute) {
                finding.setLineRange(canonical(start, end));
                finding.setAbsoluteLineNumbers(true);
                String signature = signature(finding);
                if (!seen.add(signature)) {
                    mark(finding, "POSSIBLE_DUPLICATE", "Повтор в одном фрагменте; требуется проверка.");
                } else {
                    mark(finding, "LOCATION_CHECKED",
                            "Строки " + finding.getLineRange()
                            + " находятся в исходном файле в границах фрагмента "
                            + chunk.startLine() + "-" + chunk.endLine()
                            + ". Наличие уязвимости НЕ подтверждено.");
                }
            } else if (chunk.startLine() > 1 && relative) {
                long shiftedStart = chunk.startLine() + start - 1;
                long shiftedEnd = chunk.startLine() + end - 1;
                finding.setLineRange(canonical(shiftedStart, shiftedEnd));
                mark(finding, "LOCATION_INFERRED",
                        "LLM, возможно, указала относительные строки " + raw
                        + "; предположительные абсолютные строки " + finding.getLineRange()
                        + ". Перед корреляцией с SAST проверьте вручную.");
            } else {
                mark(finding, "NEEDS_REVIEW",
                        "Строки " + raw + " вне исходного диапазона "
                        + chunk.startLine() + "-" + chunk.endLine()
                        + "; не меняем координаты без оснований.");
            }
        }
        return List.copyOf(findings);
    }

    private static String canonical(long start, long end) {
        return start == end ? Long.toString(start) : start + "-" + end;
    }

    private static String signature(Vulnerability finding) {
        return normalize(finding.getTitle()) + "|" + finding.getLineRange()
                + "|" + normalize(finding.getDescription());
    }

    private static void mark(Vulnerability finding, String status, String note) {
        finding.setValidationStatus(status);
        finding.setValidationNote(note);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT)
                .replaceAll("\\s+", " ");
    }
}
