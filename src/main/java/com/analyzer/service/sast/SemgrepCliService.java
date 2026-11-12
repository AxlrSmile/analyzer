package com.analyzer.service.sast;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs local Semgrep as a separate process, without a shell and without modifying source files.
 * The selected file list is validated before it becomes process arguments.
 */
@Service
public class SemgrepCliService {
    private static final Duration SCAN_TIMEOUT = Duration.ofMinutes(3);
    private final SemgrepReportService reports;

    public SemgrepCliService(SemgrepReportService reports) {
        this.reports = reports;
    }

    public SemgrepReportService.Report scan(Path projectRoot, List<Path> selectedFiles) throws IOException {
        Path root = projectRoot.toRealPath();
        return scanWithExecutable(root, selectedFiles, findExecutable(root));
    }

    /** Rerun the same rules against a temporary candidate, without changing the project. */
    public SemgrepReportService.Report scanTemporaryCandidate(
            Path originalProjectRoot, String sourceName, String proposedCode) throws IOException {
        Path trustedRoot = originalProjectRoot.toRealPath();
        if (!Files.isDirectory(trustedRoot) || sourceName == null || sourceName.isBlank()
                || !Path.of(sourceName).getFileName().toString().equals(sourceName)
                || sourceName.contains("/") || sourceName.contains("\\")
                || sourceName.equals(".") || sourceName.equals("..")
                || proposedCode == null || proposedCode.length() > 1_000_000) {
            throw new IOException("Недопустимые параметры повторного сканирования");
        }
        Path executable = findExecutable(trustedRoot);
        Path isolated = Files.createTempDirectory("analyzer-fix-preview-");
        Path candidate = isolated.resolve(sourceName);
        try {
            Files.writeString(candidate, proposedCode, StandardCharsets.UTF_8);
            return scanWithExecutable(isolated, List.of(candidate), executable);
        } finally {
            Files.deleteIfExists(candidate);
            Files.deleteIfExists(isolated);
        }
    }

    private SemgrepReportService.Report scanWithExecutable(
            Path root, List<Path> selectedFiles, Path executable) throws IOException {
        if (!Files.isDirectory(root)) {
            throw new IOException("Папка проекта недоступна");
        }
        if (selectedFiles == null || selectedFiles.isEmpty()) {
            throw new IOException("Нет выбранных файлов для Semgrep");
        }
        Path report = Files.createTempFile("code-analyzer-semgrep-", ".json");
        Path log = Files.createTempFile("code-analyzer-semgrep-", ".log");
        try {
            List<String> command = buildCommand(executable, root, selectedFiles, report);
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(root.toFile());
            builder.redirectErrorStream(true);
            builder.redirectOutput(log.toFile());
            Process process;
            try {
                process = builder.start();
            } catch (IOException ex) {
                throw new IOException("Не удалось запустить Semgrep (" + executable
                        + "). Проверьте установку .venv-semgrep: " + ex.getMessage(), ex);
            }
            boolean completed;
            try {
                completed = process.waitFor(SCAN_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IOException("Анализ Semgrep прерван", ex);
            }
            if (!completed) {
                process.destroyForcibly();
                throw new IOException("Semgrep превысил лимит времени (3 минуты)");
            }
            if (process.exitValue() != 0) {
                throw new IOException("Semgrep завершился с кодом " + process.exitValue()
                        + ": " + logExcerpt(log));
            }
            // Strictly validate the output; no JSON is interpreted as a successful empty scan.
            return reports.read(report);
        } finally {
            Files.deleteIfExists(report);
            Files.deleteIfExists(log);
        }
    }

    /** Visible for tests: build fixed CLI arguments without shell interpolation. */
    static List<String> buildCommand(Path executable, Path projectRoot,
                                     List<Path> selectedFiles, Path report) throws IOException {
        if (executable == null || report == null || selectedFiles == null || selectedFiles.isEmpty()) {
            throw new IOException("Не заданы параметры Semgrep");
        }
        Path root = projectRoot.toRealPath();
        List<String> args = new ArrayList<>(List.of(
                executable.toString(), "scan", "--config", "p/default",
                "--json", "--output", report.toAbsolutePath().toString(),
                "--metrics", "off", "--no-git-ignore"));
        for (Path candidate : selectedFiles) {
            if (candidate == null || !Files.isRegularFile(candidate)) {
                throw new IOException("Исходный файл недоступен: " + candidate);
            }
            Path real = candidate.toRealPath();
            if (!real.startsWith(root)) {
                throw new IOException("Запрещено сканировать файл вне проекта: " + candidate);
            }
            // ./ also protects against filenames that would otherwise look like CLI flags.
            args.add("./" + root.relativize(real).toString().replace('\\', '/'));
        }
        return List.copyOf(args);
    }

    private static Path findExecutable(Path root) {
        String override = System.getProperty("analyzer.semgrep.executable", "").trim();
        if (!override.isEmpty()) return Path.of(override);
        for (String location : List.of(".venv-semgrep/Scripts/semgrep.exe", ".venv-semgrep/bin/semgrep")) {
            Path local = root.resolve(location);
            if (Files.isRegularFile(local)) return local.toAbsolutePath();
        }
        // Fall back to PATH; process errors are explicitly reported, never treated as zero findings.
        return Path.of("semgrep");
    }

    private static String logExcerpt(Path path) {
        try {
            String value = Files.readString(path, StandardCharsets.UTF_8);
            if (value.length() > 2000) value = value.substring(value.length() - 2000);
            return value.replaceAll("[\\r\\n]+", " ");
        } catch (IOException ex) {
            return "лог запуска недоступен";
        }
    }
}
