package com.analyzer.service.fix;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 8.8: pre-export validation of UNTRUSTED LLM suggestions.
 * Invokes javac for compilation ONLY: no test execution, application launch or shell interpolation.
 * Disables annotation processing, isolates compiler input/classpath/output in a temporary directory,
 * limits heap/time, and never changes the original file. Not an OS-level security sandbox.
 */
@Service
public class FixValidationService {
    private static final Duration COMPILER_TIMEOUT = Duration.ofSeconds(15);
    private static final int DIAGNOSTIC_LIMIT = 3_500;
    private final FixReviewService review;

    public FixValidationService(FixReviewService review) {
        this.review = review;
    }

    public enum Status { PASSED, FAILED, NOT_CHECKED }

    public record Result(Status compilation, Status api, Status overall, String details) {
        public Result {
            if (compilation == null || api == null || overall == null || details == null) {
                throw new IllegalArgumentException("Поля результата проверки не должны быть пустыми");
            }
        }

        public String summary() {
            return "Компиляция: " + compilation + " | API: " + api + " | Итог: " + overall;
        }

        public String asText(FixProposal proposal) {
            return "Fix Validation Agent 8.8 — предварительный отчёт\n"
                    + "Файл: " + proposal.sourcePath().getFileName() + "\n"
                    + "Модель: " + proposal.modelName() + "\n"
                    + "SHA-256 оригинала: " + proposal.baselineSha256() + "\n"
                    + summary() + "\n\n" + details + "\n\n"
                    + "Semgrep и функциональные тесты проверяются отдельно. "
                    + "Даже PASSED не означает доказанную безопасность или корректность поведения.\n";
        }
    }

    public Result validate(FixProposal proposal) throws IOException {
        review.ensureUnchanged(proposal);
        if (proposal.originalContent() == null || proposal.proposedContent() == null) {
            throw new IOException("Отсутствует исходник или предложение");
        }
        if (proposal.proposedContent().isBlank() || proposal.proposedContent().indexOf('\0') >= 0
                || proposal.proposedContent().getBytes(StandardCharsets.UTF_8).length
                   > FixReviewService.MAX_SOURCE_BYTES) {
            throw new IOException("Предложенный текст не является допустимым исходником");
        }
        String filename = proposal.sourcePath().getFileName().toString();
        if (!filename.endsWith(".java")) {
            return new Result(Status.NOT_CHECKED, Status.NOT_CHECKED, Status.NOT_CHECKED,
                    "Автоматическая компиляция доступна только для Java-файлов .java");
        }
        if (!proposal.originalContent().equals(Files.readString(proposal.sourcePath(), StandardCharsets.UTF_8))) {
            throw new IOException("Исходный текст не соответствует исходному файлу");
        }
        FixApiCompatibility.Check api = FixApiCompatibility.compare(filename,
                proposal.originalContent(), proposal.proposedContent());
        CompileCheck compile = compareCompilation(filename,
                proposal.originalContent(), proposal.proposedContent());
        Status overall = api.status() == Status.FAILED || compile.status == Status.FAILED
                ? Status.FAILED
                : api.status() == Status.PASSED && compile.status == Status.PASSED
                    ? Status.PASSED : Status.NOT_CHECKED;
        return new Result(compile.status, api.status(), overall,
                "Проверка Java: " + compile.details + "\n\nПроверка API: " + api.details()
                    + "\n\nОригинальный файл не изменён. Исправление требует ручного ревью, "
                    + "повторной проверки Semgrep и функциональных тестов.");
    }

    private record CompileCheck(Status status, String details) { }
    private record Attempt(boolean ok, boolean supported, String diagnostics) { }

    private static CompileCheck compareCompilation(String filename, String before, String after) {
        Path javac = compilerPath();
        if (javac == null) {
            return new CompileCheck(Status.NOT_CHECKED, "javac отсутствует — используйте JDK 21.");
        }
        try {
            Attempt baseline = compileOnce(javac, filename, before);
            Attempt candidate = compileOnce(javac, filename, after);
            if (!baseline.supported || !candidate.supported) {
                return new CompileCheck(Status.NOT_CHECKED,
                        "Компилятор недоступен или превысил лимит времени. " + candidate.diagnostics);
            }
            if (baseline.ok && candidate.ok) {
                return new CompileCheck(Status.PASSED,
                        "Оригинал и предложение компилируются независимо с JDK и без сторонних библиотек.");
            }
            if (baseline.ok) {
                return new CompileCheck(Status.FAILED,
                        "Оригинал компилируется, предложение НЕ компилируется. " + candidate.diagnostics);
            }
            return new CompileCheck(Status.NOT_CHECKED,
                    "Оригинал не компилируется изолированно (например, нужны внешние зависимости). "
                    + "Проверка предложения неокончательна. "
                    + (candidate.ok ? "Предложение отдельно компилируется."
                            : "Ошибки предложения: " + candidate.diagnostics));
        } catch (IOException ex) {
            return new CompileCheck(Status.NOT_CHECKED,
                    "Компилятор не удалось запустить: " + shortText(ex.getMessage()));
        }
    }

    private static Path compilerPath() {
        Path home = Path.of(System.getProperty("java.home", ""));
        Path javac = home.resolve("bin").resolve(System.getProperty("os.name", "").toLowerCase()
                .contains("win") ? "javac.exe" : "javac");
        return Files.isRegularFile(javac) ? javac : null;
    }

    private static Attempt compileOnce(Path javac, String filename, String text) throws IOException {
        Path temp = Files.createTempDirectory("fix-validation-88-");
        try {
            Path sourceDir = Files.createDirectory(temp.resolve("source"));
            Path classDir = Files.createDirectory(temp.resolve("classes"));
            Path emptyPath = Files.createDirectory(temp.resolve("empty"));
            Path input = sourceDir.resolve(filename);
            Files.writeString(input, text, StandardCharsets.UTF_8);
            Path log = temp.resolve("javac.log");
            List<String> args = List.of(javac.toString(), "-J-Xmx128m", "-encoding", "UTF-8",
                    "-proc:none", "-implicit:none", "-classpath", emptyPath.toString(),
                    "-sourcepath", emptyPath.toString(), "-d", classDir.toString(), input.toString());
            ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(temp.toFile());
            builder.redirectErrorStream(true);
            builder.redirectOutput(log.toFile());
            Process process = builder.start();
            boolean complete;
            try {
                complete = process.waitFor(COMPILER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                return new Attempt(false, false, "Компиляция прервана");
            }
            if (!complete) {
                process.destroyForcibly();
                try { process.waitFor(2, TimeUnit.SECONDS); } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                return new Attempt(false, false, "Превышен лимит компиляции 15 секунд");
            }
            String diagnostics = Files.exists(log) ? shortText(Files.readString(log, StandardCharsets.UTF_8)
                    .replace(input.toString(), filename)) : "";
            return new Attempt(process.exitValue() == 0, true, diagnostics);
        } finally {
            try (var paths = Files.walk(temp)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (IOException ignored) { /* temporary only */ }
                });
            }
        }
    }

    private static String shortText(String message) {
        if (message == null) return "";
        String clean = message.strip();
        return clean.length() > DIAGNOSTIC_LIMIT
                ? clean.substring(0, DIAGNOSTIC_LIMIT) + " ... [диагностика ограничена]" : clean;
    }
}
