package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
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

    // Внедряем все три сервиса (SOLID: Dependency Inversion)
    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser) {
        this.projectScanner = projectScanner;
        this.fileAnalyzer = fileAnalyzer;
        this.codeParser = codeParser;
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
                // 1. Сканируем и получаем сырые файлы
                List<File> rawFiles = projectScanner.scanDirectory(selectedDirectory);
                System.out.println("Найдено файлов для анализа: " + rawFiles.size());
                System.out.println("--- Старт обработки файлов ---");

                int totalChunks = 0;

                for (File file : rawFiles) {
                    // 2. Читаем файл и преобразуем в доменную модель
                    SourceFile sourceFile = fileAnalyzer.analyzeFile(file);

                    // 3. Разбиваем файл на чанки для Ollama
                    List<String> chunks = codeParser.splitIntoChunks(sourceFile);
                    totalChunks += chunks.size();

                    // Логируем промежуточный результат в консоль
                    System.out.printf("Файл: %s | Язык: %s | Размер: %d байт | Чанков: %d%n",
                            sourceFile.getName(),
                            sourceFile.getExtension(),
                            sourceFile.getSizeInBytes(),
                            chunks.size()
                    );

                    // Выведем структуру первого чанка одного из файлов для наглядности
                    if (!chunks.isEmpty() && sourceFile.getName().equals("MainController.java")) {
                        System.out.println("\n--- Пример заголовка чанка для ИИ ---");
                        System.out.println(chunks.get(0).substring(0, Math.min(200, chunks.get(0).length())) + "...");
                        System.out.println("-------------------------------------\n");
                    }
                }

                System.out.println("--- Обработка завершена ---");
                System.out.println("Всего подготовлено чанков для отправки в ИИ: " + totalChunks);

            } catch (IOException e) {
                System.err.println("Ошибка при обработке проекта: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}