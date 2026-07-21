package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.fix.FileFixService;
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
import javafx.scene.control.cell.CheckBoxTreeCell;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.*;
import javafx.scene.web.WebView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.StringConverter;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class MainController {

    @FXML private Button selectFolderButton;
    @FXML private Button clearButton;
    @FXML private Button scanButton;
    @FXML private Button exportPdfButton;
    @FXML private Button pasteCodeButton;
    @FXML private Button fixAllButton;
    @FXML private Button fixCurrentFileButton;

    @FXML private TreeView<File> fileTreeView;
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
    private final PdfReportService pdfReportService;
    private final FileFixService fileFixService;

    private final ObservableList<SourceFile> scannedFiles = FXCollections.observableArrayList();
    private File selectedProjectFolder = null;

    private final Parser markdownParser = Parser.builder().build();
    private final HtmlRenderer htmlRenderer = HtmlRenderer.builder().build();
    private final StringBuilder chatHistoryHtml = new StringBuilder();

    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser,
                          OllamaClient ollamaClient,
                          PdfReportService pdfReportService,
                          FileFixService fileFixService) {
        this.projectScanner = projectScanner;
        this.fileAnalyzer = fileAnalyzer;
        this.codeParser = codeParser;
        this.ollamaClient = ollamaClient;
        this.pdfReportService = pdfReportService;
        this.fileFixService = fileFixService;
    }

    @FXML
    public void initialize() {
        titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));

        // Кастомные ячейки дерева с чекбоксами и динамической подсветкой найденных уязвимостей
        fileTreeView.setCellFactory(tv -> new CheckBoxTreeCell<File>(
                item -> item instanceof CheckBoxTreeItem<File> cb ? cb.selectedProperty() : null,
                new StringConverter<TreeItem<File>>() {
                    @Override
                    public String toString(TreeItem<File> treeItem) {
                        return (treeItem != null && treeItem.getValue() != null) ? treeItem.getValue().getName() : "";
                    }

                    @Override
                    public TreeItem<File> fromString(String string) {
                        return null;
                    }
                }
        ) {
            @Override
            public void updateItem(File item, boolean empty) {
                super.updateItem(item, empty);

                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                    setStyle("");
                    return;
                }

                // Проверяем, просканирован ли данный файл
                SourceFile matchedFile = scannedFiles.stream()
                        .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(item.getAbsolutePath()))
                        .findFirst()
                        .orElse(null);

                if (item.isFile() && matchedFile != null) {
                    int vulnCount = matchedFile.getVulnerabilities() != null ? matchedFile.getVulnerabilities().size() : 0;

                    if (vulnCount > 0) {
                        // Файл содержит уязвимости: красный цвет + количество
                        setText(item.getName() + " ⚠️ (" + vulnCount + ")");
                        setStyle("-fx-text-fill: #c0392b; -fx-font-weight: bold;");
                    } else {
                        // Чистый файл: зеленый цвет
                        setText(item.getName() + " ✅");
                        setStyle("-fx-text-fill: #27ae60; -fx-font-weight: normal;");
                    }
                } else {
                    // Папки или еще не просканированные файлы
                    setText(item.getName());
                    setStyle("-fx-text-fill: #2c3e50;");
                }
            }
        });

        // Отслеживание выбора файла в дереве для вывода уязвимостей в таблицу
        fileTreeView.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null && newVal.getValue() != null && newVal.getValue().isFile()) {
                File selectedFile = newVal.getValue();
                scannedFiles.stream()
                        .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(selectedFile.getAbsolutePath()))
                        .findFirst()
                        .ifPresent(this::showVulnerabilitiesForFile);
            }
        });

        vulnerabilitiesTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                showVulnerabilityDetails(newSelection);
            }
        });

        // Привязка событий к кнопкам
        selectFolderButton.setOnAction(event -> handleSelectFolderClick());
        clearButton.setOnAction(event -> handleClearProjectClick());
        scanButton.setOnAction(event -> handleStartScanClick());
        pasteCodeButton.setOnAction(event -> handlePasteAndAnalyzeCode());
        exportPdfButton.setOnAction(event -> handleExportPdfClick());
        sendPromptButton.setOnAction(event -> handleSendPromptClick());
        promptInputField.setOnAction(event -> handleSendPromptClick());
        fixCurrentFileButton.setOnAction(event -> handleFixCurrentFileClick());
        fixAllButton.setOnAction(event -> handleFixAllClick());

        // Горячая клавиша Ctrl+V для вставки кода из буфера обмена
        Platform.runLater(() -> {
            if (pasteCodeButton.getScene() != null) {
                pasteCodeButton.getScene().getAccelerators().put(
                        new KeyCodeCombination(KeyCode.V, KeyCombination.CONTROL_DOWN),
                        this::handlePasteAndAnalyzeCode
                );
            }
        });

        resetChatHtml();
    }

    /**
     * Выбор папки проекта и построение дерева с чекбоксами
     */
    private void handleSelectFolderClick() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом");
        Stage stage = (Stage) selectFolderButton.getScene().getWindow();
        File folder = directoryChooser.showDialog(stage);

        if (folder != null && folder.exists()) {
            this.selectedProjectFolder = folder;
            buildFileTree(folder);
            scanButton.setDisable(false);
            appendMessageToChatHtml("Система", "📁 Загружен проект: `" + folder.getName() + "`. Выберите файлы/папки в дереве и нажмите **«Запустить анализ выбранных»**.");
        }
    }

    /**
     * Полная очистка состояния проекта и выбор нового
     */
    private void handleClearProjectClick() {
        selectedProjectFolder = null;
        scannedFiles.clear();
        fileTreeView.setRoot(null);
        vulnerabilitiesTable.getItems().clear();
        scanButton.setDisable(true);
        resetChatHtml();
        appendMessageToChatHtml("Система", "🧹 Проект и результаты анализа успешно очищены. Выберите новую папку для анализа.");
    }

    private void buildFileTree(File rootFolder) {
        CheckBoxTreeItem<File> rootItem = createTreeItem(rootFolder);
        rootItem.setExpanded(true);
        fileTreeView.setRoot(rootItem);
        fileTreeView.setShowRoot(true);
    }

    private CheckBoxTreeItem<File> createTreeItem(File file) {
        CheckBoxTreeItem<File> item = new CheckBoxTreeItem<>(file);
        item.setSelected(true); // По умолчанию все элементы выбраны

        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File child : files) {
                    if (!child.getName().startsWith(".") && !child.getName().equalsIgnoreCase("target") && !child.getName().equalsIgnoreCase("build")) {
                        item.getChildren().add(createTreeItem(child));
                    }
                }
            }
        }
        return item;
    }

    /**
     * Анализ только отмеченных чекбоксами файлов
     */
    private void handleStartScanClick() {
        if (fileTreeView.getRoot() == null) return;

        List<File> selectedFiles = new ArrayList<>();
        collectSelectedFiles((CheckBoxTreeItem<File>) fileTreeView.getRoot(), selectedFiles);

        if (selectedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Вы не выбрали ни одного файла для анализа!");
            alert.showAndWait();
            return;
        }

        scannedFiles.clear();
        vulnerabilitiesTable.getItems().clear();
        resetChatHtml();

        scanButton.setDisable(true);
        selectFolderButton.setDisable(true);
        scanButton.setText("Идет анализ (" + selectedFiles.size() + " файлов)...");

        Task<Void> scanTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                for (File file : selectedFiles) {
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
            selectFolderButton.setDisable(false);
            scanButton.setText("🚀 Запустить анализ выбранных");

            // Обновляем отображение дерева, чтобы применились статусы ⚠️ и ✅
            fileTreeView.refresh();

            appendMessageToChatHtml("Система", "✅ **Анализ выбранных файлов завершен!** Просканировано файлов: " + scannedFiles.size());
        });

        scanTask.setOnFailed(e -> {
            scanButton.setDisable(false);
            selectFolderButton.setDisable(false);
            scanButton.setText("🚀 Запустить анализ выбранных");
            appendMessageToChatHtml("Система", "❌ **Ошибка во время анализа файлов.**");
        });

        Thread thread = new Thread(scanTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void collectSelectedFiles(CheckBoxTreeItem<File> item, List<File> result) {
        if (item.isSelected() || item.isIndeterminate()) {
            File file = item.getValue();
            if (file != null && file.isFile()) {
                result.add(file);
            }
            for (TreeItem<File> child : item.getChildren()) {
                collectSelectedFiles((CheckBoxTreeItem<File>) child, result);
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
                "### ⚠️ %s\n\n**Критичность:** `%s`  \n**Диапазон строк:** `%s`\n\n#### Описание:\n%s\n\n#### Рекомендация:\n%s",
                vulnerability.getTitle(), vulnerability.getSeverity(), vulnerability.getLineRange(),
                vulnerability.getDescription(), vulnerability.getRecommendation()
        );
        appendMessageToChatHtml("ИИ-Анализатор", markdownReport);
    }

    private void handleExportPdfClick() {
        if (scannedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Сначала необходимо просканировать проект!");
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
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "PDF-отчет успешно сформирован и сохранен!");
                alert.showAndWait();
            } catch (Exception e) {
                Alert alert = new Alert(Alert.AlertType.ERROR, "Не удалось создать PDF-отчет: " + e.getMessage());
                alert.showAndWait();
            }
        }
    }

    private void handlePasteAndAnalyzeCode() {
        Dialog<String> dialog = new Dialog<>();
        dialog.setTitle("Быстрый анализ кода");
        dialog.setHeaderText("Вставьте фрагмент кода для анализа (Ctrl+V)");

        ButtonType analyzeButtonType = new ButtonType("Анализировать", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(analyzeButtonType, ButtonType.CANCEL);

        TextArea textArea = new TextArea();
        textArea.setPromptText("Вставьте ваш Java/Spring код сюда...");
        textArea.setPrefRowCount(15);
        textArea.setPrefColumnCount(60);
        textArea.setWrapText(true);

        Clipboard clipboard = Clipboard.getSystemClipboard();
        if (clipboard.hasString()) {
            textArea.setText(clipboard.getString());
        }

        dialog.getDialogPane().setContent(textArea);
        Platform.runLater(textArea::requestFocus);

        dialog.setResultConverter(dialogButton -> dialogButton == analyzeButtonType ? textArea.getText() : null);

        dialog.showAndWait().ifPresent(codeContent -> {
            if (codeContent == null || codeContent.trim().isEmpty()) return;

            String snippetName = "Snippet_" + System.currentTimeMillis() + ".java";
            SourceFile virtualFile = new SourceFile(snippetName, null, "java", codeContent.getBytes().length, codeContent);

            pasteCodeButton.setDisable(true);
            appendMessageToChatHtml("Система", "⏳ *Выполняется экспресс-анализ вставленного фрагмента кода...*");

            Task<List<Vulnerability>> analyzeTask = new Task<>() {
                @Override
                protected List<Vulnerability> call() throws Exception {
                    return ollamaClient.analyzeCodeChunk(codeContent);
                }
            };

            analyzeTask.setOnSucceeded(e -> {
                pasteCodeButton.setDisable(false);
                List<Vulnerability> vulnerabilities = analyzeTask.getValue();
                virtualFile.setVulnerabilities(vulnerabilities);
                scannedFiles.add(virtualFile);

                if (vulnerabilities.isEmpty()) {
                    appendMessageToChatHtml("ИИ-Консультант", "✅ **Уязвимости во вставленном фрагменте кода не обнаружены!**");
                } else {
                    appendMessageToChatHtml("ИИ-Консультант", "⚠️ **Анализ завершен!** Обнаружено уязвимостей: **" + vulnerabilities.size() + "**.");
                }
            });

            analyzeTask.setOnFailed(e -> {
                pasteCodeButton.setDisable(false);
                appendMessageToChatHtml("Система", "❌ **Ошибка во время анализа фрагмента кода.**");
            });

            Thread thread = new Thread(analyzeTask);
            thread.setDaemon(true);
            thread.start();
        });
    }

    private void handleSendPromptClick() {
        String question = promptInputField.getText().trim();
        TreeItem<File> selectedTreeItem = fileTreeView.getSelectionModel().getSelectedItem();
        Vulnerability selectedVuln = vulnerabilitiesTable.getSelectionModel().getSelectedItem();

        if (question.isEmpty()) return;

        if (selectedTreeItem == null || selectedTreeItem.getValue() == null || selectedVuln == null) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Пожалуйста, выберите файл в дереве и конкретную уязвимость в таблице!");
            alert.showAndWait();
            return;
        }

        SourceFile selectedSourceFile = scannedFiles.stream()
                .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(selectedTreeItem.getValue().getAbsolutePath()))
                .findFirst()
                .orElse(null);

        if (selectedSourceFile == null) return;

        appendMessageToChatHtml("Вы", question);
        promptInputField.clear();
        sendPromptButton.setDisable(true);

        Task<String> chatTask = new Task<>() {
            @Override
            protected String call() {
                return ollamaClient.askQuestionAboutVulnerability(selectedSourceFile, selectedVuln, question);
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

    private void handleFixCurrentFileClick() {
        TreeItem<File> selectedTreeItem = fileTreeView.getSelectionModel().getSelectedItem();
        if (selectedTreeItem == null || selectedTreeItem.getValue() == null) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Сначала выберите файл из дерева слева!");
            alert.showAndWait();
            return;
        }

        SourceFile selectedFile = scannedFiles.stream()
                .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(selectedTreeItem.getValue().getAbsolutePath()))
                .findFirst()
                .orElse(null);

        if (selectedFile == null || selectedFile.getVulnerabilities().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION, "В этом файле уязвимости не найдены!");
            alert.showAndWait();
            return;
        }

        fixCurrentFileButton.setDisable(true);
        appendMessageToChatHtml("Система", "⏳ *ИИ формирует исправленный вариант файла " + selectedFile.getName() + "...*");

        Task<String> fixTask = new Task<>() {
            @Override
            protected String call() throws Exception {
                return ollamaClient.fixSourceFile(selectedFile);
            }
        };

        fixTask.setOnSucceeded(e -> {
            try {
                String fixedCode = fixTask.getValue();
                fixCurrentFileButton.setDisable(false);
                String createdFileName = fileFixService.saveFixedVersionAsTxt(selectedFile, fixedCode);
                appendMessageToChatHtml("ИИ-Консультант", "✅ **Исправленный вариант сохранен в файл:** `" + createdFileName + "`\n\n```java\n" + fixedCode + "\n```");
            } catch (Exception ex) {
                fixCurrentFileButton.setDisable(false);
                appendMessageToChatHtml("Система", "❌ **Ошибка сохранения файла:** " + ex.getMessage());
            }
        });

        fixTask.setOnFailed(e -> {
            fixCurrentFileButton.setDisable(false);
            appendMessageToChatHtml("Система", "❌ **Ошибка генерации исправления ИИ.**");
        });

        Thread thread = new Thread(fixTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void handleFixAllClick() {
        List<SourceFile> problematicFiles = scannedFiles.stream()
                .filter(f -> !f.getVulnerabilities().isEmpty() && f.getAbsolutePath() != null)
                .toList();

        if (problematicFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION, "Нет просканированных файлов с уязвимостями!");
            alert.showAndWait();
            return;
        }

        fixAllButton.setDisable(true);

        Task<Void> fixAllTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                int total = problematicFiles.size();
                for (int i = 0; i < total; i++) {
                    SourceFile file = problematicFiles.get(i);
                    int currentNum = i + 1;
                    Platform.runLater(() -> fixAllButton.setText("Исправление (" + currentNum + "/" + total + ")..."));
                    try {
                        String fixedCode = ollamaClient.fixSourceFile(file);
                        fileFixService.saveFixedVersionAsTxt(file, fixedCode);
                    } catch (Exception e) {
                        System.err.println("Ошибка генерации для " + file.getName() + ": " + e.getMessage());
                    }
                }
                return null;
            }
        };

        fixAllTask.setOnSucceeded(e -> {
            fixAllButton.setDisable(false);
            fixAllButton.setText("⚡ Исправить весь проект");
            Alert alert = new Alert(Alert.AlertType.INFORMATION, "Исправленные варианты (.txt) успешно созданы!");
            alert.showAndWait();
        });

        fixAllTask.setOnFailed(e -> {
            fixAllButton.setDisable(false);
            fixAllButton.setText("⚡ Исправить весь проект");
        });

        Thread thread = new Thread(fixAllTask);
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