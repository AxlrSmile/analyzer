package com.analyzer.service.fix;

import com.analyzer.service.sast.SemgrepCliService;
import com.analyzer.service.sast.SemgrepReportService;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Safety boundary for generated fixes: detect stale source, compare, export without overwrite,
 * and optionally rerun Semgrep against an isolated temporary candidate.
 */
@Service
public class FixReviewService {
    static final long MAX_SOURCE_BYTES = 1_000_000;
    private final SemgrepCliService semgrep;

    public FixReviewService(SemgrepCliService semgrep) {
        this.semgrep = semgrep;
    }

    public record Recheck(int baselineFindings, int candidateFindings,
                          List<String> baselineRules, List<String> candidateRules) {
        public Recheck {
            baselineRules = List.copyOf(baselineRules);
            candidateRules = List.copyOf(candidateRules);
        }
    }

    static String hash(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 недоступен", e);
        }
    }

    static byte[] readSource(Path path) throws IOException {
        if (path == null || !Files.isRegularFile(path) || Files.size(path) > MAX_SOURCE_BYTES) {
            throw new IOException("Исходный файл не найден или превышает 1 МБ");
        }
        byte[] data = Files.readAllBytes(path);
        if (data.length > MAX_SOURCE_BYTES || containsNul(data)) {
            throw new IOException("Файл слишком большой или содержит двоичные данные");
        }
        // Refuse lossy fallback conversions when computing a revision lock.
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
            decoder.decode(java.nio.ByteBuffer.wrap(data));
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new IOException("Для предложений исправлений поддерживается UTF-8 без повреждённых символов", e);
        }
        return data;
    }

    private static boolean containsNul(byte[] bytes) {
        for (byte b : bytes) if (b == 0) return true;
        return false;
    }

    public void ensureUnchanged(FixProposal proposal) throws IOException {
        if (proposal == null || proposal.sourcePath() == null || proposal.baselineSha256() == null) {
            throw new IOException("Предложение исправления отсутствует");
        }
        // toRealPath detects deleted/replaced links; the hash checks the file bytes.
        Path real = proposal.sourcePath().toRealPath();
        if (!real.equals(proposal.sourcePath())
                || !hash(readSource(real)).equals(proposal.baselineSha256())) {
            throw new IOException("Исходный файл изменился после генерации. Повторите анализ и запрос исправления.");
        }
    }

    public Path exportSeparate(FixProposal proposal, Path destination) throws IOException {
        ensureUnchanged(proposal);
        if (destination == null || proposal.proposedContent() == null
                || proposal.proposedContent().isBlank()) {
            throw new IOException("Не задан путь или предложенный код отсутствует");
        }
        Path target = destination.toAbsolutePath().normalize();
        if (target.equals(proposal.sourcePath())
                || Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Существующий файл нельзя перезаписывать. Выберите новое имя.");
        }
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("Папка для сохранения не существует");
        }
        // CREATE_NEW is atomic: avoid clobbering existing files even on races/symlinks.
        Files.writeString(target, proposal.proposedContent(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return target;
    }

    public Recheck recheckWithSemgrep(FixProposal proposal, Path projectRoot) throws IOException {
        ensureUnchanged(proposal);
        Path root = projectRoot.toRealPath();
        if (!Files.isDirectory(root) || !proposal.sourcePath().startsWith(root)) {
            throw new IOException("Выбранный исходный файл находится вне проекта");
        }
        SemgrepReportService.Report before = semgrep.scan(root, List.of(proposal.sourcePath()));
        if (before.hasErrors()) throw new IOException("Semgrep сообщил ошибки на оригинале; сравнение недостоверно");
        SemgrepReportService.Report after = semgrep.scanTemporaryCandidate(
                root, proposal.sourcePath().getFileName().toString(), proposal.proposedContent());
        if (after.hasErrors()) throw new IOException("Semgrep сообщил ошибки на предложении; сравнение недостоверно");
        return new Recheck(before.findings().size(), after.findings().size(),
                before.findings().stream().map(SemgrepReportService.Finding::ruleId).toList(),
                after.findings().stream().map(SemgrepReportService.Finding::ruleId).toList());
    }

    /** Human-readable line-by-line preview (not a claim of a minimal unified diff). */
    public static String diffPreview(String original, String proposed) {
        String[] a = original.split("\\R", -1), b = proposed.split("\\R", -1);
        if (a.length > 400 || b.length > 400) {
            return "Файл больше 400 строк: автоматический diff ограничен. "
                    + "Проверьте обе версии на вкладках «Исходник» и «Предложение».";
        }
        // LCS gives useful aligned + and - lines for small source files.
        int[][] lcs = new int[a.length + 1][b.length + 1];
        for (int i = a.length - 1; i >= 0; i--) for (int j = b.length - 1; j >= 0; j--) {
            lcs[i][j] = a[i].equals(b[j]) ? 1 + lcs[i + 1][j + 1]
                    : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
        StringBuilder out = new StringBuilder("Построчное сравнение (- удалено, + добавлено). Не является patch-файлом.\n\n");
        int i = 0, j = 0, shown = 0;
        while ((i < a.length || j < b.length) && shown < 500) {
            if (i < a.length && j < b.length && a[i].equals(b[j])) { i++; j++; continue; }
            if (j < b.length && (i == a.length || lcs[i][j + 1] >= lcs[i + 1][j])) {
                out.append("+ ").append(j + 1).append(": ").append(b[j++]).append('\n');
            } else {
                out.append("- ").append(i + 1).append(": ").append(a[i++]).append('\n');
            }
            shown++;
        }
        if (shown >= 500) out.append("... Предпросмотр ограничен 500 строками.\n");
        return out.toString();
    }
}
