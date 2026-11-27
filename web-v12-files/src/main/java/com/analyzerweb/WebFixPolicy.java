package com.analyzerweb;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

/** Restricts browser fix previews to small Java source files and human-review metadata. */
public final class WebFixPolicy {
    private static final Set<String> SEVERITIES = Set.of("HIGH", "MEDIUM", "LOW");
    private WebFixPolicy() { }

    public record Input(String simpleName, int lines) { }

    public static Input check(WebFixService.PreviewRequest request) {
        if (request == null || request.source() == null || request.fileName() == null
                || request.model() == null || request.model().isBlank()
                || request.model().length() > 100 || request.finding() == null) {
            throw new IllegalArgumentException("Выберите Java-файл, модель и одну находку");
        }
        String path = request.fileName().replace('\\', '/');
        if (path.startsWith("/") || path.matches("(?i)^[a-z]:.*")
                || path.contains("//") || path.equals("..") || path.startsWith("../")
                || path.contains("/../") || path.contains("/./")) {
            throw new IllegalArgumentException("Недопустимый путь файла");
        }
        String name = path.substring(path.lastIndexOf('/') + 1);
        WebUploadPolicy.checkedName(name);
        if (!name.toLowerCase(Locale.ROOT).endsWith(".java")) {
            throw new IllegalArgumentException("Предварительная проверка исправлений пока доступна только для .java");
        }
        byte[] bytes = request.source().getBytes(StandardCharsets.UTF_8);
        WebUploadPolicy.checkBytes(bytes);
        WebFixService.FindingInput finding = request.finding();
        if (!shortText(finding.title(), 240) || !shortText(finding.description(), 3000)
                || !shortText(finding.recommendation(), 3000)
                || !shortText(finding.lines(), 60) || !shortText(finding.cwe(), 40)
                || !shortText(finding.origin(), 20)
                || !SEVERITIES.contains(finding.severity())) {
            throw new IllegalArgumentException("Некорректные сведения о находке");
        }
        if (!Set.of("Semgrep", "LLM").contains(finding.origin())) {
            throw new IllegalArgumentException("Неизвестный источник находки");
        }
        if (!finding.lines().matches("[0-9]{1,5}(?:[-–][0-9]{1,5})?")) {
            throw new IllegalArgumentException("Некорректный номер строки находки");
        }
        int count = (int) request.source().lines().count();
        if (count == 0) throw new IllegalArgumentException("Пустой исходный код");
        int first = Integer.parseInt(finding.lines().split("[-–]")[0]);
        if (first < 1 || first > count) {
            throw new IllegalArgumentException("Строка находки выходит за пределы исходника");
        }
        return new Input(name, count);
    }

    private static boolean shortText(String value, int max) {
        return value != null && value.length() <= max;
    }
}
