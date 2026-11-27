package com.analyzerweb;

import com.analyzer.domain.model.Vulnerability;

/**
 * Web-only, metadata-only explanation of the LLM evidence quality.
 * Do not copy the model's raw quote, source excerpt, validation note or prompt
 * into this DTO: users may export it and browser extensions may read it.
 */
public final class WebFindingDiagnostics {
    private WebFindingDiagnostics() { }

    public record Diagnostic(String modelOutputStatus, String reasonCode,
                             String explanation, String nextStep) { }

    public static Diagnostic inspect(Vulnerability v) {
        if (v == null) throw new IllegalArgumentException("finding is null");
        String validation = v.getValidationStatus();
        if ("SAST_REPORTED".equals(validation)) {
            return new Diagnostic("NOT_APPLICABLE", "SAST_SIGNAL",
                    "Сигнал Semgrep сохранён отдельно. Он не доказывает эксплуатацию уязвимости.",
                    "Сверьте правило и фактический путь данных в исходнике.");
        }
        String status = v.getModelOutputStatus();
        if ("PARTIAL_RESPONSE".equals(status)) {
            return new Diagnostic(status, "PARTIAL_CANDIDATES",
                    "После повторной проверки часть кандидатов модели оказалась некорректной или потерялась. Ответ неполный.",
                    "Проверьте исходную находку вручную. При необходимости повторите аудит.");
        }
        if ("EVIDENCE_UNVERIFIED".equals(status)) {
            // Match only our known validator messages; never echo arbitrary model text.
            String note = v.getValidationNote() == null ? "" : v.getValidationNote();
            String reason = note.contains("не привела точную однострочную цитату")
                    || note.contains("Слишком короткая цитата")
                    ? "EVIDENCE_FORMAT"
                    : note.contains("Цитата evidence не найдена")
                    ? "EVIDENCE_MISMATCH"
                    : "EVIDENCE_NOT_VERIFIED";
            String message = switch (reason) {
                case "EVIDENCE_FORMAT" -> "Цитата модели отсутствует или имеет недопустимый формат.";
                case "EVIDENCE_MISMATCH" -> "Цитата модели не совпадает с заявленными строками исходника.";
                default -> "Строго подтвердить цитату модели по исходному файлу не удалось: формат или совпадение неизвестны.";
            };
            return new Diagnostic(status, reason, message,
                    "Сравните строки находки с исходником; не считайте её подтверждённой.");
        }
        if ("NEEDS_REVIEW".equals(validation) || "LOCATION_INFERRED".equals(validation)) {
            return new Diagnostic(safeStatus(status), "LOCATION_NEEDS_REVIEW",
                    "Местоположение находки не подтверждено автоматически.",
                    "Откройте исходный файл и проверьте строки вручную.");
        }
        if ("EVIDENCE_MATCHED".equals(status) && "LOCATION_CHECKED".equals(validation)) {
            return new Diagnostic(status, "CITATION_MATCHED",
                    "Номер строки и цитата совпали с оригиналом; это не подтверждает наличие уязвимости.",
                    "Оцените путь данных и риск вручную.");
        }
        return new Diagnostic(safeStatus(status), "EVIDENCE_STATUS_UNKNOWN",
                "Недостаточно данных о качестве цитаты LLM. Отсутствие подтверждения не означает безопасность.",
                "Изучите находку вручную и повторите аудит при необходимости.");
    }

    private static String safeStatus(String status) {
        return switch (status == null ? "" : status) {
            case "NOT_ASSESSED", "EVIDENCE_MATCHED", "EVIDENCE_UNVERIFIED", "PARTIAL_RESPONSE" -> status;
            default -> "NOT_ASSESSED";
        };
    }
}
