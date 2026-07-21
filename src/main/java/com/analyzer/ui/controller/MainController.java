package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.report.PdfReportService;
import com.analyzer.service.scanner.ProjectScanner;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.web.WebView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class MainController {

    @FXML private Button scanButton;
    @FXML private Button exportPdfButton; // Кнопка экспорта в PDF
    @FXML private ListView<SourceFile> filesListView;
    @FXML private TableView<Vulnerability> vulnerabilitiesTable;
    @FXML private TableColumn<Vulnerability, String> titleColumn;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> linesColumn;

    @FXML private WebView chatWebView;
    @FXML private TextField promptInputField;
    @FXML private Button sendPromptButton;

    private final ProjectScanner projectScanner;
    private final FileAnalyzer fileAnalyzer;
    private final CodeParser codeParser;
    private final OllamaClient ollamaClient;
    private final PdfReportService pdfReportService; // Сервис генерации PDF

    private final ObservableList<SourceFile> scannedFiles = FXCollections.observableArrayList();

    // Flexmark парсеры для перевода Markdown -> HTML
    private final Parser markdownParser = Parser.builder().build();
    private final HtmlRenderer htmlRenderer = HtmlRenderer.builder().build();

    // Накопитель HTML историй сообщений
    private final StringBuilder chatHistoryHtml = new StringBuilder();

    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser,
                          OllamaClient ollamaClient,
                          PdfReportService pdfReportService) {
        this.projectScanner = projectScanner;
        this.fileAnalyzer = fileAnalyzer;
        this.codeParser = codeParser;
        this.ollamaClient = ollamaClient;
        this.pdfReportService = pdfReportService;
    }

    @FXML
    public void initialize() {
        titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));

        filesListView.setItems(scannedFiles);

        filesListView.setCellFactory(param -> new ListCell<>() {
            @Override
            protected void updateItem(SourceFile item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    long count = item.getVulnerabilities().size();
                    setText(item.getName() + (count > 0 ? " [!] (" + count + ")" : " (ОК)"));
                }
            }
        });

        filesListView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                showVulnerabilitiesForFile(newSelection);
            }
        });

        vulnerabilitiesTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                showVulnerabilityDetails(newSelection);
            }
        });

        scanButton.setOnAction(event -> handleScanButtonClick());
        exportPdfButton.setOnAction(event -> handleExportPdfClick()); // Обработчик экспорта
        sendPromptButton.setOnAction(event -> handleSendPromptClick());
        promptInputField.setOnAction(event -> handleSendPromptClick());

        resetChatHtml();
    }

    private void handleScanButtonClick() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом проекта");

        Stage stage = (Stage) scanButton.getScene().getWindow();
        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            scannedFiles.clear();
            vulnerabilitiesTable.getItems().clear();
            resetChatHtml();

            scanButton.setDisable(true);
            scanButton.setText("Идет интеллектуальный анализ ИИ... Пожалуйста, подождите");

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
                            Platform.runLater(() -> scannedFiles.add(sourceFile));

                        } catch (IOException e) {
                            System.err.println("Ошибка при анализе файла " + file.getName() + ": " + e.getMessage());
                        }
                    }
                    return null;
                }
            };

            scanTask.setOnSucceeded(e -> {
                scanButton.setDisable(false);
                scanButton.setText("Выбрать проект для сканирования");
            });

            scanTask.setOnFailed(e -> {
                scanButton.setDisable(false);
                scanButton.setText("Выбрать проект для сканирования");
            });

            Thread thread = new Thread(scanTask);
            thread.setDaemon(true);
            thread.start();
        }
    }

    private void handleExportPdfClick() {
        if (scannedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Внимание");
            alert.setHeaderText(null);
            alert.setContentText("Сначала необходимо просканировать проект!");
            alert.showAndWait();
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Сохранить PDF отчет");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PDF Documents (*.pdf)", "*.pdf"));
        fileChooser.setInitialFileName("security_report.pdf");

        Stage stage = (Stage) exportPdfButton.getScene().getWindow();
        File saveFile = fileChooser.showSaveDialog(stage);

        if (saveFile != null) {
            try {
                pdfReportService.generatePdfReport(scannedFiles, saveFile.getAbsolutePath());

                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle("Успех");
                alert.setHeaderText(null);
                alert.setContentText("PDF-отчет успешно сформирован и сохранен!");
                alert.showAndWait();
            } catch (Exception e) {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.setTitle("Ошибка");
                alert.setHeaderText(null);
                alert.setContentText("Не удалось создать PDF-отчет: " + e.getMessage());
                alert.showAndWait();
            }
        }
    }

    private void showVulnerabilitiesForFile(SourceFile sourceFile) {
        vulnerabilitiesTable.setItems(FXCollections.observableArrayList(sourceFile.getVulnerabilities()));
        resetChatHtml();
    }

    private void showVulnerabilityDetails(Vulnerability vulnerability) {
        resetChatHtml();

        String markdownReport = String.format(
                "### ⚠️ %s\n\n" +
                        "**Критичность:** `%s`  \n" +
                        "**Диапазон строк:** `%s`\n\n" +
                        "#### Описание:\n%s\n\n" +
                        "#### Рекомендация по исправлению:\n%s",
                vulnerability.getTitle(),
                vulnerability.getSeverity(),
                vulnerability.getLineRange(),
                vulnerability.getDescription(),
                vulnerability.getRecommendation()
        );

        appendMessageToChatHtml("ИИ-Анализатор", markdownReport);
    }

    private void handleSendPromptClick() {
        String question = promptInputField.getText().trim();
        SourceFile selectedFile = filesListView.getSelectionModel().getSelectedItem();
        Vulnerability selectedVuln = vulnerabilitiesTable.getSelectionModel().getSelectedItem();

        if (question.isEmpty()) return;

        if (selectedFile == null || selectedVuln == null) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Внимание");
            alert.setHeaderText(null);
            alert.setContentText("Пожалуйста, выберите файл и конкретную уязвимость в таблице!");
            alert.showAndWait();
            return;
        }

        appendMessageToChatHtml("Вы", question);
        promptInputField.clear();
        sendPromptButton.setDisable(true);

        Task<String> chatTask = new Task<>() {
            @Override
            protected String call() {
                return ollamaClient.askQuestionAboutVulnerability(selectedFile, selectedVuln, question);
            }
        };

        chatTask.setOnSucceeded(e -> {
            sendPromptButton.setDisable(false);
            appendMessageToChatHtml("ИИ-Консультант", chatTask.getValue());
        });

        chatTask.setOnFailed(e -> {
            sendPromptButton.setDisable(false);
            appendMessageToChatHtml("Система", "**Ошибка получения ответа от ИИ.**");
        });

        Thread thread = new Thread(chatTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void resetChatHtml() {
        chatHistoryHtml.setLength(0);
        chatHistoryHtml.append("<!DOCTYPE html><html><head><style>")
                .append("body { font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 10px; padding: 0; }")
                .append(".msg-card { background: #ffffff; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }")
                .append(".sender { font-weight: bold; font-size: 12px; color: #34495e; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }")
                .append("p { margin: 4px 0; color: #2c3e50; font-size: 13px; line-height: 1.5; }")
                .append("code { background: #eef2f7; color: #c0392b; padding: 2px 5px; border-radius: 4px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }")
                .append("pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }")
                .append("pre code { background: none; color: #d4d4d4; padding: 0; }")
                .append("h3 { color: #c0392b; margin-top: 0; font-size: 15px; }")
                .append("h4 { color: #2c3e50; margin: 8px 0 4px 0; font-size: 13px; }")
                .append("</style></head><body>");

        renderHtml();
    }

    private void appendMessageToChatHtml(String sender, String markdownText) {
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));

        chatHistoryHtml.append("<div class='msg-card'>")
                .append("<div class='sender'>").append(sender).append("</div>")
                .append(htmlContent)
                .append("</div>");

        renderHtml();
    }

    private void renderHtml() {
        String fullHtml = chatHistoryHtml.toString() + "<script>window.scrollTo(0, document.body.scrollHeight);</script></body></html>";
        Platform.runLater(() -> chatWebView.getEngine().loadContent(fullHtml));
    }
}