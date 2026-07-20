package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.scanner.ProjectScanner;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.List;

@Component
public class MainController {

    @FXML
    private Button scanButton;

    private final ProjectScanner projectScanner;
    private final FileAnalyzer fileAnalyzer;
    private final CodeParser codeParser;
    private final OllamaClient ollamaClient;

    // Внедряем все необходимые компоненты через конструктор
    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser,
                          OllamaClient ollamaClient) {
        this.projectScanner = projectScanner;
        this.fileAnalyzer = fileAnalyzer;
        this.codeParser = codeParser;
        this.ollamaClient = ollamaClient;
    }

    @FXML
    public void initialize() {
        scanButton.setOnAction(event -> handleScanButtonClick());
    }

    private void handleScanButtonClick() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом проекта");

        Stage stage = (Stage) scanButton.getScene().getWindow();
        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            System.out.println("Выбрана директория: " + selectedDirectory.getAbsolutePath());

            try {
                // 1. Сканируем проект
                List<File> rawFiles = projectScanner.scanDirectory(selectedDirectory);
                System.out.println("Найдено файлов для анализа: " + rawFiles.size());
                System.out.println("--- Старт интеллектуального анализа ---");

                for (File file : rawFiles) {
                    // 2. Читаем файл и определяем метаданные
                    SourceFile sourceFile = fileAnalyzer.analyzeFile(file);

                    // 3. Разбиваем на чанки
                    List<String> chunks = codeParser.splitIntoChunks(sourceFile);

                    System.out.printf("Анализируем файл: %s (%d чанков)...%n", sourceFile.getName(), chunks.size());

                    for (String chunk : chunks) {
                        // 4. Отправляем каждый фрагмент в локальную LLM через Ollama
                        List<Vulnerability> vulnerabilities = ollamaClient.analyzeCodeChunk(chunk);

                        // Если уязвимости найдены — выводим их в консоль
                        if (!vulnerabilities.isEmpty()) {
                            System.out.printf("[!] В файле %s обнаружено уязвимостей: %d%n", sourceFile.getName(), vulnerabilities.size());
                            for (Vulnerability vuln : vulnerabilities) {
                                System.out.println("--------------------------------------------------");
                                System.out.println("УЯЗВИМОСТЬ: " + vuln.getTitle());
                                System.out.println("КРИТИЧНОСТЬ: " + vuln.getSeverity());
                                System.out.println("СТРОКИ: " + vuln.getLineRange());
                                System.out.println("ОПИСАНИЕ: " + vuln.getDescription());
                                System.out.println("РЕКОМЕНДАЦИЯ: " + vuln.getRecommendation());
                                System.out.println("--------------------------------------------------");
                            }
                        }
                    }
                }

                System.out.println("--- Интеллектуальный анализ полностью завершен ---");

            } catch (IOException e) {
                System.err.println("Ошибка при анализе проекта: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}