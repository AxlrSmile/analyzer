package com.analyzerweb;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.scanner.UnifiedScanService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Semaphore;

/** Uploads are temporary and are never executed or copied into the desktop project. */
@Service
public class WebScanService {
    private final UnifiedScanService analyzer;
    private final Semaphore oneScanAtATime = new Semaphore(1);

    public WebScanService(UnifiedScanService analyzer) {
        this.analyzer = analyzer;
    }

    public ScanView scan(List<MultipartFile> uploads, String model) throws IOException {
        if (uploads == null || uploads.isEmpty() || uploads.size() > WebUploadPolicy.MAX_FILES) {
            throw new IllegalArgumentException("Выберите от 1 до 5 исходных файлов");
        }
        List<WebZipPolicy.Source> inputs = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        long total = 0;
        for (MultipartFile upload : uploads) {
            if (upload == null) throw new IllegalArgumentException("Пустой элемент загрузки");
            String name = WebUploadPolicy.checkedName(upload.getOriginalFilename());
            if (!unique.add(name.toLowerCase(Locale.ROOT)))
                throw new IllegalArgumentException("Повторяющееся имя файла: " + name);
            if (upload.getSize() <= 0 || upload.getSize() > WebUploadPolicy.MAX_FILE_BYTES)
                throw new IllegalArgumentException("Файл превышает 256 КБ: " + name);
            total += upload.getSize();
            if (total > WebUploadPolicy.MAX_TOTAL_BYTES)
                throw new IllegalArgumentException("Общий размер файлов превышает 512 КБ");
            byte[] bytes = upload.getBytes();
            WebUploadPolicy.checkBytes(bytes);
            inputs.add(new WebZipPolicy.Source(name, bytes));
        }
        return scanPrepared(inputs, model);
    }

    public ScanView scanZip(MultipartFile zip, String model) throws IOException {
        if (zip == null || zip.getOriginalFilename() == null
                || !zip.getOriginalFilename().toLowerCase(Locale.ROOT).endsWith(".zip")
                || zip.getSize() <= 0 || zip.getSize() > WebZipPolicy.MAX_ARCHIVE_BYTES) {
            throw new IllegalArgumentException("Выберите ZIP-архив не больше 2 МБ");
        }
        return scanPrepared(WebZipPolicy.read(zip.getBytes()), model);
    }

    private ScanView scanPrepared(List<WebZipPolicy.Source> inputs, String model) throws IOException {
        if (model == null || model.isBlank() || model.length() > 100)
            throw new IllegalArgumentException("Выберите модель Ollama");
        if (!oneScanAtATime.tryAcquire()) throw new ScanBusyException();
        Path workspace = null;
        try {
            workspace = Files.createTempDirectory("code-security-web-");
            List<java.io.File> files = new ArrayList<>();
            for (WebZipPolicy.Source input : inputs) {
                Path output = workspace.resolve(input.path()).normalize();
                if (!output.startsWith(workspace)) throw new IllegalArgumentException("Некорректный путь исходного файла");
                Files.createDirectories(output.getParent());
                Files.write(output, input.bytes());
                files.add(output.toFile());
            }
            UnifiedScanService.ScanResult scan = analyzer.scan(workspace, files, model);
            List<FileView> results = scan.files().stream().map(WebScanService::fileView).toList();
            return new ScanView(scan.files().size(), scan.analyzedByLlm(), scan.partialByLlm(),
                    scan.failedByLlm(), scan.sastCompleted(), scan.sastFindings(),
                    scan.diagnostics(), results);
        } finally {
            if (workspace != null) clearWorkspace(workspace);
            oneScanAtATime.release();
        }
    }

    private static FileView fileView(SourceFile file) {
        List<FindingView> findings = file.getVulnerabilities().stream()
                .map(WebScanService::findingView).toList();
        // Source is returned only to the requesting local browser for a code preview.
        // The website intentionally removes it from exported JSON reports.
        String name = file.getRelativePath() == null || file.getRelativePath().isBlank()
                ? file.getName() : file.getRelativePath().replace('\\', '/');
        return new FileView(name, file.getLinesOfCode(), findings, file.getContent());
    }

    private static FindingView findingView(Vulnerability v) {
        String status = v.getValidationStatus();
        String origin = "SAST_REPORTED".equals(status) ? "Semgrep" : "LLM";
        return new FindingView(origin, clip(v.getTitle(), 240), clip(v.getSeverity(), 20),
                clip(v.getCwe(), 40), clip(v.getLineRange(), 60),
                clip(v.getDescription(), 3000), clip(v.getRecommendation(), 3000),
                clip(status, 80), clip(v.getAiReviewStatus(), 80),
                WebFindingDiagnostics.inspect(v));
    }

    private static String clip(String text, int max) {
        if (text == null) return "";
        return text.length() > max ? text.substring(0, max) + "…" : text;
    }

    private static void clearWorkspace(Path root) {
        try (var paths = Files.walk(root)) {
            for (Path file : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(file);
            }
        } catch (IOException ex) {
            // Cleanup diagnostics avoid exposing a temporary file path in the browser.
            System.err.println("Веб-аудит: не удалось полностью удалить временную папку: "
                    + ex.getClass().getSimpleName());
        }
    }

    public record FindingView(String origin, String title, String severity, String cwe,
                              String lines, String description, String recommendation,
                              String validation, String aiReview,
                              WebFindingDiagnostics.Diagnostic evidenceDiagnostic) { }
    public record FileView(String name, long lines, List<FindingView> findings, String source) { }
    public record ScanView(int loadedFiles, int llmComplete, int llmPartial,
                           int llmFailed, boolean sastCompleted, int sastFindings,
                           List<String> diagnostics, List<FileView> files) { }
    public static class ScanBusyException extends RuntimeException { }
}
