package com.analyzerweb;

/** Interpretation of validation outcomes, never proof of exploitability or safety. */
public final class WebFixComparison {
    private WebFixComparison() { }

    public record Assessment(String category, String explanation, boolean changed) { }

    public static Assessment assess(String original, String proposed, String compilation,
                                    String api, String semgrepStatus,
                                    Integer before, Integer after) {
        if (original == null || proposed == null || proposed.isBlank()
                || original.equals(proposed)) {
            return new Assessment("NO_CHANGE", "Предложение не меняет оригинальный код.", false);
        }
        if (!"PASSED".equals(compilation)) {
            return new Assessment("NOT_VALIDATED", "Компиляция Java не подтверждена.", true);
        }
        if (!"PASSED".equals(api)) {
            return new Assessment("API_UNVERIFIED", "Совместимость API требует проверки.", true);
        }
        if (!"COMPLETED".equals(semgrepStatus) || before == null || after == null
                || before < 0 || after < 0) {
            return new Assessment("SAST_NOT_CHECKED", "Нет сравнимого повторного Semgrep.", true);
        }
        if (after > before) {
            return new Assessment("STATIC_REGRESSION", "Число предупреждений Semgrep увеличилось.", true);
        }
        if (after < before) {
            return new Assessment("STATIC_SIGNALS_REDUCED", "Предупреждений Semgrep стало меньше; это не доказательство безопасности.", true);
        }
        return new Assessment("STATIC_SIGNALS_UNCHANGED", "Число предупреждений Semgrep не изменилось.", true);
    }
}
