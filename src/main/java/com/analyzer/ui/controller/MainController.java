package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.scanner.ProjectScanner;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class MainController {

    @FXML private Button scanButton;
    @FXML private ListView<SourceFile> filesListView;
    @FXML private TableView<Vulnerability> vulnerabilitiesTable;
    @FXML private TableColumn<Vulnerability, String> titleColumn;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> linesColumn;
    @FXML private TextArea detailsTextArea;

    private final ProjectScanner projectScanner;
    private final FileAnalyzer fileAnalyzer;
    private final CodeParser codeParser;
    private final OllamaClient ollamaClient;

    // Специальный список JavaFX, который автоматически обновляет UI при изменении данных
    private final ObservableList<SourceFile> scannedFiles = FXCollections.observableArrayList();

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
        // 1. Настраиваем привязку колонок таблицы к полям модели Vulnerability
        titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));

        // 2. Связываем ObservableList с ListView
        filesListView.setItems(scannedFiles);

        // 3. Кастомизируем отображение файлов в списке, чтобы выводилось только имя, а не весь путь
        filesListView.setCellFactory(param -> new ListCell<>() {
            @Override
            protected void updateItem(SourceFile item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    // Покажем имя и количество найденных уязвимостей рядом
                    long count = item.getVulnerabilities().size();
                    setText(item.getName() + (count > 0 ? " [!] (" + count + ")" : " (ОК)"));
                }
            }
        });

        // 4. Слушатель кликов по файлам в списке
        filesListView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                showVulnerabilitiesForFile(newSelection);
            }
        });

        // 5. Слушатель кликов по строкам таблицы уязвимостей
        vulnerabilitiesTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                showVulnerabilityDetails(newSelection);
            }
        });

        scanButton.setOnAction(event -> handleScanButtonClick());
    }

    private void handleScanButtonClick() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом проекта");

        Stage stage = (Stage) scanButton.getScene().getWindow();
        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            // Очищаем старые результаты перед новым сканированием
            scannedFiles.clear();
            vulnerabilitiesTable.getItems().clear();
            detailsTextArea.clear();

            // Блокируем кнопку на время сканирования
            scanButton.setDisable(true);
            scanButton.setText("Идет интеллектуальный анализ ИИ... Пожалуйста, подождите");

            // Создаем фоновую задачу JavaFX Task
            Task<Void> scanTask = new Task<>() {
                @Override
                protected Void call() throws Exception {
                    List<File> rawFiles = projectScanner.scanDirectory(selectedDirectory);

                    for (File file : rawFiles) {
                        try {
                            SourceFile sourceFile = fileAnalyzer.analyzeFile(file);
                            List<String> chunks = codeParser.splitIntoChunks(sourceFile);
                            List<Vulnerability> allFileVulns = new ArrayList<>();

                            for (String chunk : chunks) {
                                List<Vulnerability> chunkVulns = ollamaClient.analyzeCodeChunk(chunk);
                                allFileVulns.addAll(chunkVulns);
                            }

                            sourceFile.setVulnerabilities(allFileVulns);

                            // Безопасно обновляем UI из фонового потока
                            Platform.runLater(() -> scannedFiles.add(sourceFile));

                        } catch (IOException e) {
                            System.err.println("Ошибка при анализе файла " + file.getName() + ": " + e.getMessage());
                        }
                    }
                    return null;
                }
            };

            // Что делать, когда задача успешно завершится
            scanTask.setOnSucceeded(e -> {
                scanButton.setDisable(false);
                scanButton.setText("Выбрать проект для сканирования");

                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle("Анализ завершен");
                alert.setHeaderText(null);
                alert.setContentText("Проект успешно проанализирован локальным ИИ!");
                alert.showAndWait();
            });

            // Что делать в случае критической ошибки
            scanTask.setOnFailed(e -> {
                scanButton.setDisable(false);
                scanButton.setText("Выбрать проект для сканирования");
                Throwable ex = scanTask.getException();
                ex.printStackTrace();
            });

            // Запускаем задачу в отдельном системном потоке
            Thread thread = new Thread(scanTask);
            thread.setDaemon(true); // Поток закроется сам при закрытии приложения
            thread.start();
        }
    }

    /**
     * Загружает список уязвимостей конкретного файла в таблицу справа.
     */
    private void showVulnerabilitiesForFile(SourceFile sourceFile) {
        vulnerabilitiesTable.setItems(FXCollections.observableArrayList(sourceFile.getVulnerabilities()));
        detailsTextArea.clear(); // Очищаем поле деталей при переключении файла
    }

    /**
     * Отображает подробный текстовый отчет об уязвимости в нижней текстовой области.
     */
    private void showVulnerabilityDetails(Vulnerability vulnerability) {
        String details = String.format(
                "УЯЗВИМОСТЬ: %s\n" +
                        "КРИТИЧНОСТЬ: %s\n" +
                        "СТРОКИ В КОДЕ: %s\n\n" +
                        "ОПИСАНИЕ:\n%s\n\n" +
                        "РЕКОМЕНДАЦИЯ ПО ИСПРАВЛЕНИЮ:\n%s",
                vulnerability.getTitle(),
                vulnerability.getSeverity(),
                vulnerability.getLineRange(),
                vulnerability.getDescription(),
                vulnerability.getRecommendation()
        );
        detailsTextArea.setText(details);
    }
}