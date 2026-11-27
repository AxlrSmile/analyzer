package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.agent.SecurityReviewerAgent;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.CodeChunk;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.sast.FindingCorrelationService;
import com.analyzer.service.sast.SemgrepCliService;
import com.analyzer.service.sast.SemgrepReportService;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Coordinates local SAST and LLM analysis, retaining partial results and error diagnostics. */
@Service
public class UnifiedScanService {
    private static final long MAX_SOURCE_SIZE = 1_000_000; // Skip unbounded or binary-sized input.
    private static final Set<String> SOURCE_EXTENSIONS = Set.of(
            ".java", ".kt", ".scala", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
            ".py", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".php", ".rb",
            ".go", ".rs", ".cs", ".sql");

    private final FileAnalyzer fileAnalyzer;
    private final CodeParser parser;
    private final SecurityScannerAgent llmAgent;
    private final SemgrepCliService semgrep;
    private final FindingCorrelationService correlation;
    private final SecurityReviewerAgent reviewer;
    private final FindingDeduplicationService deduplicator = new FindingDeduplicationService();
    private static final int REVIEW_LIMIT_PER_SCAN = 10;

    public record ScanResult(List<SourceFile> files, int analyzedByLlm, int failedByLlm,
                             boolean sastCompleted, int sastFindings, int skippedTargets,
                             int unrelatedFindings, int possibleOverlaps,
                             List<String> diagnostics, int aiReviewed, int aiReviewFailed,
                             int aiReviewSkipped, int partialByLlm,
                             List<String> partialFiles, List<String> failedFiles) {
        public ScanResult {
            files = List.copyOf(files);
            diagnostics = List.copyOf(diagnostics);
            partialFiles = List.copyOf(partialFiles);
            failedFiles = List.copyOf(failedFiles);
        }
        // Compatibility for existing tests and direct ScanResult construction.
        public ScanResult(List<SourceFile> files, int analyzedByLlm, int failedByLlm,
                          boolean sastCompleted, int sastFindings, int skippedTargets,
                          int unrelatedFindings, int possibleOverlaps,
                          List<String> diagnostics, int aiReviewed, int aiReviewFailed,
                          int aiReviewSkipped) {
            this(files, analyzedByLlm, failedByLlm, sastCompleted, sastFindings,
                    skippedTargets, unrelatedFindings, possibleOverlaps, diagnostics,
                    aiReviewed, aiReviewFailed, aiReviewSkipped, 0, List.of(), List.of());
        }
    }

    @Autowired
    public UnifiedScanService(FileAnalyzer fileAnalyzer, CodeParser parser,
                              SecurityScannerAgent llmAgent, SemgrepCliService semgrep,
                              FindingCorrelationService correlation,
                              SecurityReviewerAgent reviewer) {
        this.fileAnalyzer = fileAnalyzer;
        this.parser = parser;
        this.llmAgent = llmAgent;
        this.semgrep = semgrep;
        this.correlation = correlation;
        this.reviewer = reviewer;
    }

    // Backward-compatible constructor used by existing unit tests.
    public UnifiedScanService(FileAnalyzer fileAnalyzer, CodeParser parser,
                              SecurityScannerAgent llmAgent, SemgrepCliService semgrep,
                              FindingCorrelationService correlation) {
        this(fileAnalyzer, parser, llmAgent, semgrep, correlation, null);
    }

    public ScanResult scan(Path projectRoot, List<File> selectedFiles, String modelName) throws IOException {
        Path root = projectRoot.toRealPath();
        if (!Files.isDirectory(root)) throw new IOException("Папка проекта не существует");
        if (selectedFiles == null || selectedFiles.isEmpty()) {
            throw new IOException("Нет выбранных файлов для анализа");
        }
        List<String> diagnostics = new ArrayList<>();
        List<SourceFile> files = new ArrayList<>();
        int skipped = 0;
        for (File file : selectedFiles) {
            if (file == null || !file.isFile() || !isSource(file.getName())
                    || file.length() > MAX_SOURCE_SIZE) {
                skipped++;
                continue;
            }
            Path real = file.toPath().toRealPath();
            if (!real.startsWith(root)) {
                skipped++;
                diagnostics.add("Файл вне папки проекта пропущен: " + file.getName());
                continue;
            }
            try {
                SourceFile source = fileAnalyzer.analyzeFile(file);
                // Correct inaccurate legacy metrics from FileAnalyzerImpl.
                source.setRelativePath(root.relativize(real).toString());
                source.setLinesOfCode(source.getContent() == null ? 0 : source.getContent().lines().count());
                files.add(source);
            } catch (Exception ex) {
                skipped++;
                diagnostics.add("Ошибка чтения " + file.getName() + ": " + safeMessage(ex));
            }
        }
        if (files.isEmpty()) {
            throw new IOException("Нет поддерживаемых читаемых исходных файлов. Выберите .java, .py, .js и др.");
        }
        SemgrepReportService.Report sast = null;
        try {
            sast = semgrep.scan(root, files.stream().map(SourceFile::getPath).toList());
            if (sast.hasErrors()) {
                diagnostics.add("Semgrep вернул " + sast.errors().size()
                        + " диагностических ошибок; результат может быть неполным.");
            }
        } catch (IOException ex) {
            diagnostics.add("Semgrep не завершил проверку: " + safeMessage(ex));
        }

        int successful = 0;
        int failed = 0;
        int partial = 0;
        List<String> partialFiles = new ArrayList<>();
        List<String> failedFiles = new ArrayList<>();
        for (SourceFile file : files) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("Анализ прерван");
            if (file.getContent() == null || file.getContent().isBlank()) {
                failed++;
                failedFiles.add(file.getRelativePath().replace('\\', '/'));
                diagnostics.add("LLM не проверила " + file.getName()
                        + ": файл пустой; отсутствие находок не означает безопасный код");
                continue;
            }
            try {
                List<Vulnerability> findings = new ArrayList<>();
                List<String> chunkProblems = new ArrayList<>();
                int chunksCompleted = 0;
                List<CodeChunk> located = parser.splitIntoLocatedChunks(file);
                if (located == null) {
                    // Compatibility with older mocked parsers: only an EXACTLY
                    // full-file, single chunk may be analyzed without metadata.
                    List<String> legacy = parser.splitIntoChunks(file);
                    if (legacy == null || legacy.size() != 1
                            || !legacy.getFirst().equals(file.getContent())) {
                        throw new IllegalStateException("Парсер не вернул проверяемые координаты фрагментов");
                    }
                    findings.addAll(llmAgent.scanChunk(legacy.getFirst(), file.getName(), modelName));
                    chunksCompleted++;
                } else {
                    // Non-empty source must never be reported as successfully scanned
                    // when a parser unexpectedly produces zero chunks.
                    if (located.isEmpty()) {
                        throw new IllegalStateException(
                                "Парсер не вернул фрагменты для непустого исходного файла");
                    }
                    for (CodeChunk chunk : located) {
                        try {
                            findings.addAll(llmAgent.scanLocatedChunk(chunk, file.getName(), modelName));
                            chunksCompleted++;
                        } catch (RuntimeException ex) {
                            chunkProblems.add("фрагмент " + chunk.startLine() + "-" + chunk.endLine()
                                    + ": " + safeMessage(ex));
                        }
                    }
                    if (chunksCompleted == 0) {
                        throw new IllegalStateException("ни один фрагмент не проанализирован: "
                                + String.join("; ", chunkProblems));
                    }
                }
                List<Vulnerability> unique = deduplicator.removeExactDuplicates(findings);
                int merged = findings.size() - unique.size();
                if (merged > 0) {
                    diagnostics.add("LLM: объединено " + merged + " точных повторов для "
                            + file.getName() + " (перекрывающиеся фрагменты).");
                }
                file.setVulnerabilities(new ArrayList<>(unique));
                long unverified = unique.stream().filter(v -> "EVIDENCE_UNVERIFIED".equals(v.getModelOutputStatus())
                        || "PARTIAL_RESPONSE".equals(v.getModelOutputStatus())).count();
                if (!chunkProblems.isEmpty() || unverified > 0) {
                    partial++;
                    partialFiles.add(file.getRelativePath().replace('\\', '/'));
                    diagnostics.add("LLM частично проверила " + file.getName() + ": "
                            + (unverified > 0 ? unverified + " непроверенных/неполных находок. " : "")
                            + String.join("; ", chunkProblems));
                } else {
                    successful++;
                }
            } catch (RuntimeException ex) {
                failed++;
                failedFiles.add(file.getRelativePath().replace('\\', '/'));
                diagnostics.add("LLM не проверила " + file.getName() + ": " + safeMessage(ex));
            }
        }

        FindingCorrelationService.Summary stats = new FindingCorrelationService.Summary(0, 0, 0);
        if (sast != null) {
            try {
                stats = correlation.merge(root, files, sast);
            } catch (IOException ex) {
                diagnostics.add("Не удалось сопоставить часть Semgrep-находок: " + safeMessage(ex));
            }
        }
        int reviewed = 0;
        int reviewFailed = 0;
        int reviewSkipped = 0;
        if (reviewer != null) {
            for (SourceFile file : files) {
                for (Vulnerability finding : file.getVulnerabilities()) {
                    // Review only imported SAST findings; do not silently remove them.
                    if (!"SAST_REPORTED".equals(finding.getValidationStatus())) continue;
                    if (reviewed + reviewFailed >= REVIEW_LIMIT_PER_SCAN) {
                        reviewSkipped++;
                        continue;
                    }
                    try {
                        reviewer.review(file, finding, modelName);
                        reviewed++;
                    } catch (RuntimeException ex) {
                        reviewFailed++;
                        finding.setAiReviewStatus("NEEDS_REVIEW");
                        finding.setAiReviewNote("ИИ-ревью не выполнено: " + safeMessage(ex)
                                + ". Требуется ручная проверка.");
                        diagnostics.add("ИИ-ревью для " + file.getName() + " ("
                                + finding.getLineRange() + ") не выполнено: " + safeMessage(ex));
                    }
                }
            }
        }
        if (reviewSkipped > 0) {
            diagnostics.add("ИИ-ревью: " + reviewSkipped
                    + " SAST-находок не проверены из-за лимита " + REVIEW_LIMIT_PER_SCAN);
        }
        return new ScanResult(files, successful, failed, sast != null,
                sast == null ? 0 : sast.findings().size(), skipped,
                stats.unrelated(), stats.overlaps(), diagnostics,
                reviewed, reviewFailed, reviewSkipped,
                partial, partialFiles, failedFiles);
    }

    private static boolean isSource(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return SOURCE_EXTENSIONS.stream().anyMatch(lower::endsWith);
    }

    private static String safeMessage(Exception ex) {
        String message = ex.getMessage();
        if (message == null || message.isBlank()) return ex.getClass().getSimpleName();
        return message.length() > 250 ? message.substring(0, 250) + "..." : message;
    }
}
