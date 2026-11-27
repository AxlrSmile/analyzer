package com.analyzer.service.benchmark;

import com.analyzer.domain.model.BenchmarkResult;
import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.FileAnalyzer;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

@Service
public class BenchmarkService {

    private final OllamaClient ollamaClient;
    private final FileAnalyzer fileAnalyzer;

    public BenchmarkService(OllamaClient ollamaClient, FileAnalyzer fileAnalyzer) {
        this.ollamaClient = ollamaClient;
        this.fileAnalyzer = fileAnalyzer;
    }

    public List<BenchmarkResult> runBenchmark(List<File> testFiles, List<String> models, Consumer<String> logger) {
        List<BenchmarkResult> results = new ArrayList<>();

        for (String model : models) {
            logger.accept("Тестирование модели: " + model + "...");
            long start = System.currentTimeMillis();

            int tp = 0, fp = 0, tn = 0, fn = 0;

            for (File file : testFiles) {
                try {
                    SourceFile sourceFile = fileAnalyzer.analyzeFile(file);
                    String fileName = file.getName().toLowerCase();
                    // Если в названии есть clean, safe или fixed — считаем файл чистым
                    boolean isActuallyVulnerable = !fileName.contains("clean")
                            && !fileName.contains("fixed")
                            && !fileName.contains("safe");

                    List<Vulnerability> vulns = ollamaClient.analyzeCodeChunk(
                            sourceFile.getContent(),
                            sourceFile.getName(),
                            model
                    );

                    boolean modelDetected = vulns != null && !vulns.isEmpty();

                    if (isActuallyVulnerable && modelDetected) tp++;
                    else if (!isActuallyVulnerable && modelDetected) fp++;
                    else if (!isActuallyVulnerable && !modelDetected) tn++;
                    else if (isActuallyVulnerable && !modelDetected) fn++;

                } catch (Exception e) {
                    logger.accept("Ошибка на файле " + file.getName() + " под моделью " + model + ": " + e.getMessage());
                }
            }

            double totalTimeSec = (System.currentTimeMillis() - start) / 1000.0;
            BenchmarkResult res = new BenchmarkResult(model, testFiles.size(), tp, fp, tn, fn, totalTimeSec);
            results.add(res);

            logger.accept(String.format("Модель %s завершена: F1=%s, время=%s",
                    model, res.getF1ScoreFormatted(), res.getTotalTimeFormatted()));
        }

        return results;
    }
}