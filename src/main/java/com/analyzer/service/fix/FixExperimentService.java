package com.analyzer.service.fix;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Research notebook for evaluated LLM fixes. No candidate code or test program is ever executed.
 * Functional outcomes are explicit observations supplied by the researcher, not inferred from SAST.
 * Only file name, fingerprints, statuses and short human notes are exported; never code or full paths.
 */
@Service
public class FixExperimentService {
    public enum Status { PASSED, FAILED, SKIPPED, NOT_CHECKED }
    public enum Verdict { REJECTED, INCOMPLETE, REVIEW_REQUIRED, PRELIMINARY_PASS }

    public record Scenario(String id, String label) {
        public Scenario {
            if (id == null || id.isBlank() || label == null || label.isBlank()) {
                throw new IllegalArgumentException("Empty test scenario");
            }
        }
    }
    public record Observation(Scenario scenario, Status status) {
        public Observation {
            if (scenario == null || status == null) throw new IllegalArgumentException("Incomplete observation");
        }
    }

    public record Entry(long number, Instant recordedAt, String filename, String cwe, String model,
                        String baselineSha256, String proposalSha256, Status compilation, Status api,
                        Status sast, Integer findingsBefore, Integer findingsAfter,
                        FixCweReviewService.Status mechanism, List<Observation> functional,
                        Verdict verdict, String note) {
        public Entry {
            if (number <= 0 || recordedAt == null || filename == null || filename.isBlank()
                    || cwe == null || model == null || baselineSha256 == null || proposalSha256 == null
                    || compilation == null || api == null || sast == null || mechanism == null
                    || functional == null || functional.isEmpty() || verdict == null || note == null) {
                throw new IllegalArgumentException("Incomplete experiment entry");
            }
            functional = List.copyOf(functional);
            if ((findingsBefore == null) != (findingsAfter == null)) {
                throw new IllegalArgumentException("Incomplete SAST comparison");
            }
            if (findingsBefore != null && (findingsBefore < 0 || findingsAfter < 0 || sast != Status.PASSED)) {
                throw new IllegalArgumentException("Invalid SAST counters");
            }
        }
    }

    private final FixCweReviewService reviewer;
    private final List<Entry> entries = new ArrayList<>();

    public FixExperimentService(FixCweReviewService reviewer) {
        this.reviewer = reviewer;
    }

    public static String normalizedCwe(String raw) {
        String s = raw == null ? "" : raw.toUpperCase(Locale.ROOT).trim();
        if (s.matches("CWE-[0-9]{1,5}")) return s;
        return "CWE-OTHER";
    }

    public static List<Scenario> scenariosFor(String cwe) {
        return switch (normalizedCwe(cwe)) {
            case "CWE-22" -> List.of(new Scenario("normal", "Обычный файл внутри разрешённой папки"),
                    new Scenario("traversal", "Выход через ../ отвергнут"),
                    new Scenario("symlink", "Ссылка на внешний файл отвергнута (или SKIPPED при запрете ОС)"));
            case "CWE-89" -> List.of(new Scenario("normal", "Обычный запрос возвращает ожидаемую строку"),
                    new Scenario("injection", "Специальный ввод не расширяет результат SQL"));
            case "CWE-78" -> List.of(new Scenario("normal", "Команда работает с обычным аргументом"),
                    new Scenario("metachar", "Спецсимволы не интерпретируются как shell-инструкции"));
            case "CWE-79" -> List.of(new Scenario("normal", "Обычный HTML-контент работает"),
                    new Scenario("escape", "Специальные HTML-символы безопасно экранированы"));
            case "CWE-918" -> List.of(new Scenario("allowed", "Разрешённый URL работает"),
                    new Scenario("blocked", "Внутренний или запрещённый адрес отклоняется"));
            case "CWE-611" -> List.of(new Scenario("valid", "Обычный XML разбирается"),
                    new Scenario("external", "Внешние сущности и DTD не обрабатываются"));
            case "CWE-502" -> List.of(new Scenario("known", "Разрешённый формат читается"),
                    new Scenario("untrusted", "Недоверенный объект или тип отклоняется"));
            default -> List.of(new Scenario("normal", "Позитивный сценарий без регрессии"),
                    new Scenario("negative", "Негативный сценарий для этой CWE"));
        };
    }

    public synchronized Entry record(FixProposal proposal, String selectedCwe,
                                      FixValidationService.Result javaValidation,
                                      FixReviewService.Recheck semgrep,
                                      List<Observation> observations, String note) {
        if (proposal == null || proposal.sourcePath() == null || proposal.originalContent() == null
                || proposal.proposedContent() == null || proposal.baselineSha256() == null) {
            throw new IllegalArgumentException("Missing proposal");
        }
        String cwe = normalizedCwe(selectedCwe);
        List<Scenario> required = scenariosFor(cwe);
        if (observations == null || observations.size() != required.size()) {
            throw new IllegalArgumentException("All scenario statuses are required");
        }
        for (int i = 0; i < required.size(); i++) {
            if (observations.get(i) == null || !required.get(i).equals(observations.get(i).scenario())) {
                throw new IllegalArgumentException("Scenario list does not match CWE template");
            }
        }
        String safeNote = note == null ? "" : note.strip();
        if (safeNote.length() > 400) throw new IllegalArgumentException("Note exceeds 400 characters");
        boolean hasDecision = observations.stream().anyMatch(o -> o.status() == Status.PASSED
                || o.status() == Status.FAILED || o.status() == Status.SKIPPED);
        if (hasDecision && safeNote.isBlank()) {
            throw new IllegalArgumentException("Для результатов PASSED / FAILED / SKIPPED укажите краткое основание");
        }
        Status compilation = javaValidation == null ? Status.NOT_CHECKED
                : fromJava(javaValidation.compilation());
        Status api = javaValidation == null ? Status.NOT_CHECKED
                : fromJava(javaValidation.api());
        Status sast = semgrep == null ? Status.NOT_CHECKED : Status.PASSED;
        Integer before = semgrep == null ? null : semgrep.baselineFindings();
        Integer after = semgrep == null ? null : semgrep.candidateFindings();
        var review = reviewer.inspect(cwe, proposal.proposedContent());
        Verdict verdict = verdict(compilation, api, sast, before, after, review.status(), observations);
        Entry entry = new Entry(entries.size() + 1L, Instant.now(),
                proposal.sourcePath().getFileName().toString(), cwe,
                safeShort(proposal.modelName(), 120), proposal.baselineSha256(),
                FixReviewService.hash(proposal.proposedContent().getBytes(StandardCharsets.UTF_8)),
                compilation, api, sast, before, after, review.status(),
                observations, verdict, safeNote);
        entries.add(entry);
        return entry;
    }

    private static Status fromJava(FixValidationService.Status value) {
        return value == null ? Status.NOT_CHECKED : switch (value) {
            case PASSED -> Status.PASSED;
            case FAILED -> Status.FAILED;
            case NOT_CHECKED -> Status.NOT_CHECKED;
        };
    }

    public static Verdict verdict(Status compilation, Status api, Status sast,
                                   Integer before, Integer after, FixCweReviewService.Status mechanism,
                                   List<Observation> functional) {
        if (compilation == Status.FAILED || api == Status.FAILED
                || functional.stream().anyMatch(o -> o.status() == Status.FAILED)) {
            return Verdict.REJECTED;
        }
        if (compilation != Status.PASSED || api != Status.PASSED || sast != Status.PASSED
                || functional.stream().anyMatch(o -> o.status() != Status.PASSED)) {
            return Verdict.INCOMPLETE;
        }
        // 0->0, unknown mechanism, or no decrease cannot certify a fixed CWE.
        if (before == null || after == null || before == 0 || after >= before
                || mechanism != FixCweReviewService.Status.PATTERN_PRESENT) {
            return Verdict.REVIEW_REQUIRED;
        }
        return Verdict.PRELIMINARY_PASS; // Never a proof; manual review is still required.
    }

    public synchronized List<Entry> entries() { return List.copyOf(entries); }

    public synchronized String toCsv() {
        StringBuilder out = new StringBuilder("number;utc;file;cwe;model;source_sha256;proposal_sha256;compilation;api;semgrep;findings_before;findings_after;mechanism;functional_passed;functional_failed;functional_skipped;functional_not_checked;verdict;scenarios;note\n");
        for (Entry e : entries) {
            long passed = count(e, Status.PASSED), failed = count(e, Status.FAILED);
            long skipped = count(e, Status.SKIPPED), pending = count(e, Status.NOT_CHECKED);
            StringBuilder scenarios = new StringBuilder();
            for (Observation o : e.functional()) {
                if (!scenarios.isEmpty()) scenarios.append(" | ");
                scenarios.append(o.scenario().id()).append(":").append(o.status());
            }
            String[] fields = {Long.toString(e.number()), e.recordedAt().toString(), e.filename(),
                    e.cwe(), e.model(), e.baselineSha256(), e.proposalSha256(), e.compilation().name(),
                    e.api().name(), e.sast().name(), num(e.findingsBefore()), num(e.findingsAfter()),
                    e.mechanism().name(), Long.toString(passed), Long.toString(failed),
                    Long.toString(skipped), Long.toString(pending), e.verdict().name(),
                    scenarios.toString(), e.note()};
            for (int i = 0; i < fields.length; i++) {
                if (i > 0) out.append(';');
                out.append(csv(fields[i]));
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static String safeShort(String input, int max) {
        String normalized = input == null ? "" : input.replaceAll("[\\r\\n\\t]", " ").strip();
        return normalized.substring(0, Math.min(max, normalized.length()));
    }
    private static String num(Integer n) { return n == null ? "" : n.toString(); }
    private static long count(Entry e, Status status) {
        return e.functional().stream().filter(x -> x.status() == status).count();
    }
    private static String csv(String value) {
        String safe = value == null ? "" : value.replace("\0", "").replace("\r", " ").replace("\n", " ");
        String trimmed = safe.stripLeading();
        // A spreadsheet may evaluate cells beginning with =, +, -, @, or tab as a formula.
        if (!trimmed.isEmpty() && "=+-@".indexOf(trimmed.charAt(0)) >= 0) safe = "'" + safe;
        return '"' + safe.replace("\"", "\"\"") + '"';
    }

    public synchronized String toMarkdown() {
        StringBuilder out = new StringBuilder("# Эксперименты исправлений — версия 8.9\n\n");
        out.append("Результаты являются предварительной проверкой, а не доказательством безопасности. "
                + "Функциональные статусы введены исследователем после внешнего тестирования; "
                + "приложение не выполняет предложенный код.\n\n");
        out.append("| № | Файл | CWE | Java | API | Semgrep | Функц. P/F/S/N | Вердикт |\n");
        out.append("|---:|---|---|---|---|---|---|---|\n");
        Map<Verdict,Integer> totals = new LinkedHashMap<>();
        for (Entry e : entries) {
            totals.merge(e.verdict(), 1, Integer::sum);
            out.append('|').append(e.number()).append('|').append(md(e.filename()))
                    .append('|').append(e.cwe()).append('|').append(e.compilation())
                    .append('|').append(e.api()).append('|');
            out.append(e.findingsBefore() == null ? "NOT_CHECKED"
                    : e.findingsBefore() + " → " + e.findingsAfter());
            out.append('|').append(count(e, Status.PASSED)).append('/')
                    .append(count(e, Status.FAILED)).append('/')
                    .append(count(e, Status.SKIPPED)).append('/')
                    .append(count(e, Status.NOT_CHECKED)).append('|')
                    .append(e.verdict()).append("|\n");
        }
        out.append("\nВсего попыток: ").append(entries.size()).append(". ");
        for (Verdict v : Verdict.values()) {
            out.append(v).append(": ").append(totals.getOrDefault(v, 0)).append("; ");
        }
        out.append("\n\n**Ограничения:** Semgrep 0 → 0 не подтверждает устранение CWE; "
                + "SKIPPED не равен PASSED; компиляция не проверяет поведение. "
                + "PRELIMINARY_PASS требует ручного ревью.\n");
        return out.toString();
    }

    private static String md(String value) {
        return safeShort(value, 150).replace("|", "\\|").replace("`", "'");
    }

    public synchronized Path exportCsv(Path target) throws IOException { return export(target, "\uFEFF" + toCsv()); }
    public synchronized Path exportMarkdown(Path target) throws IOException { return export(target, toMarkdown()); }

    private Path export(Path target, String contents) throws IOException {
        if (entries.isEmpty()) throw new IOException("Журнал ещё пуст");
        if (target == null) throw new IOException("Не указан файл экспорта");
        Path absolute = target.toAbsolutePath().normalize();
        if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Нельзя перезаписывать существующий отчёт");
        }
        if (absolute.getParent() == null || !Files.isDirectory(absolute.getParent())) {
            throw new IOException("Каталог для отчёта не найден");
        }
        return Files.writeString(absolute, contents, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
