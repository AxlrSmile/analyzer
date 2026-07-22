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

    // Основные элементы управления (Вкладка "Анализ")
    @FXML private Button selectFolderButton;
    @FXML private CheckBox selectAllCheckBox;
    @FXML private Button clearButton;
    @FXML private Button scanButton;
    @FXML private Button exportPdfButton;
    @FXML private Button pasteCodeButton;
    @FXML private Button fixAllButton;
    @FXML private Button fixCurrentFileButton;

    @FXML private ComboBox<String> modelComboBox;

    @FXML private TreeView<File> fileTreeView;
    @FXML private TableView<Vulnerability> vulnerabilitiesTable;
    @FXML private TableColumn<Vulnerability, String> titleColumn;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> linesColumn;

    @FXML private WebView chatWebView;
    @FXML private TextField promptInputField;
    @FXML private Button sendPromptButton;

    // Вспомогательные элементы (Вкладка "Свободный чат")
    @FXML private ComboBox<String> chatModelComboBox;
    @FXML private Button refreshModelsButton;
    @FXML private WebView generalChatWebView;
    @FXML private TextField generalChatPromptInput;
    @FXML private Button sendGeneralChatPromptButton;
    @FXML private Button clearGeneralChatButton; // Кнопка очистки свободного чата

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

    // HTML-буферы для рендеринга WebViews
    private final StringBuilder chatHistoryHtml = new StringBuilder();
    private final StringBuilder generalChatHtml = new StringBuilder();

    // Единая история сообщений общего чата для сохранения контекста при смене моделей
    private final List<ChatMessage> generalChatHistory = new ArrayList<>();

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

    /**
     * DTO для сохранения роли и текста сообщения в истории контекста
     */
    public static class ChatMessage {
        private final String role; // "user" или "assistant"
        private final String content;

        public ChatMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public String getRole() { return role; }
        public String getContent() { return content; }
    }

    @FXML
    public void initialize() {
        // 1. Настройка таблицы уязвимостей
        titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));

        // 2. Оформление дерева файлов с чекбоксами и статусами
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

                SourceFile matchedFile = scannedFiles.stream()
                        .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(item.getAbsolutePath()))
                        .findFirst()
                        .orElse(null);

                if (item.isFile() && matchedFile != null) {
                    int vulnCount = matchedFile.getVulnerabilities() != null ? matchedFile.getVulnerabilities().size() : 0;

                    if (vulnCount > 0) {
                        setText(item.getName() + " ⚠️ (" + vulnCount + ")");
                        setStyle("-fx-text-fill: #c0392b; -fx-font-weight: bold;");
                    } else {
                        setText(item.getName() + " ✅");
                        setStyle("-fx-text-fill: #27ae60; -fx-font-weight: normal;");
                    }
                } else {
                    setText(item.getName());
                    setStyle("-fx-text-fill: #2c3e50;");
                }
            }
        });

        // 3. Слушатели выбора файлов и уязвимостей
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

        // 4. Назначение обработчиков событий для первой вкладки
        selectAllCheckBox.setOnAction(event -> handleSelectAllToggle());
        selectFolderButton.setOnAction(event -> handleSelectFolderClick());
        clearButton.setOnAction(event -> handleClearProjectClick());
        scanButton.setOnAction(event -> handleStartScanClick());
        pasteCodeButton.setOnAction(event -> handlePasteAndAnalyzeCode());
        exportPdfButton.setOnAction(event -> handleExportPdfClick());
        sendPromptButton.setOnAction(event -> handleSendPromptClick());
        promptInputField.setOnAction(event -> handleSendPromptClick());
        fixCurrentFileButton.setOnAction(event -> handleFixCurrentFileClick());
        fixAllButton.setOnAction(event -> handleFixAllClick());

        // 5. Назначение обработчиков событий для общего чата (своевременная проверка на null)
        if (sendGeneralChatPromptButton != null) {
            sendGeneralChatPromptButton.setOnAction(event -> handleSendGeneralChatPrompt());
        }
        if (generalChatPromptInput != null) {
            generalChatPromptInput.setOnAction(event -> handleSendGeneralChatPrompt());
        }
        if (refreshModelsButton != null) {
            refreshModelsButton.setOnAction(event -> loadAvailableModels());
        }
        if (clearGeneralChatButton != null) {
            clearGeneralChatButton.setOnAction(event -> handleClearGeneralChat());
        }

        // Hotkey Ctrl+V
        Platform.runLater(() -> {
            if (pasteCodeButton.getScene() != null) {
                pasteCodeButton.getScene().getAccelerators().put(
                        new KeyCodeCombination(KeyCode.V, KeyCombination.CONTROL_DOWN),
                        this::handlePasteAndAnalyzeCode
                );
            }
        });

        // Сброс и запуск
        resetChatHtml();
        resetGeneralChatHtml();
        loadAvailableModels();
    }

    /**
     * Загрузка списка доступных моделей Ollama в ComboBox компоненты
     */
    private void loadAvailableModels() {
        Task<List<String>> task = new Task<>() {
            @Override
            protected List<String> call() {
                return ollamaClient.getAvailableModels();
            }
        };

        task.setOnSucceeded(e -> {
            List<String> models = task.getValue();
            if (models != null && !models.isEmpty()) {
                ObservableList<String> modelList = FXCollections.observableArrayList(models);
                if (modelComboBox != null) {
                    modelComboBox.setItems(modelList);
                    modelComboBox.getSelectionModel().selectFirst();
                }
                if (chatModelComboBox != null) {
                    chatModelComboBox.setItems(modelList);
                    chatModelComboBox.getSelectionModel().selectFirst();
                }
            }
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Сброс истории свободного чата и очистка контекста диалога
     */
    @FXML
    private void handleClearGeneralChat() {
        // 1. Очищаем накопленный контекст диалога
        generalChatHistory.clear();

        // 2. Сбрасываем HTML в WebView
        resetGeneralChatHtml();

        // 3. Выводим приветственное/системное сообщение
        appendGeneralChatMessage("Система", "🧹 **Чат и контекст диалога успешно сброшены.**");
    }

    /**
     * Отправка запроса в свободной вкладке чата с нативной поддержкой ролей в Ollama Chat API
     */
    private void handleSendGeneralChatPrompt() {
        if (generalChatPromptInput == null) return;

        String prompt = generalChatPromptInput.getText().trim();
        String selectedModel = (chatModelComboBox != null) ? chatModelComboBox.getValue() : null;

        if (prompt.isEmpty()) return;

        if (selectedModel == null || selectedModel.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Пожалуйста, выберите модель для общения!");
            alert.showAndWait();
            return;
        }

        // 1. Отображаем сообщение пользователя в WebView
        appendGeneralChatMessage("Вы", prompt);

        // 2. Добавляем реплику пользователя в историю контекста
        generalChatHistory.add(new ChatMessage("user", prompt));

        generalChatPromptInput.clear();
        if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(true);

        // 3. Асинхронный вызов Chat API с передачей всей коллекции history
        Task<String> chatTask = new Task<>() {
            @Override
            protected String call() {
                // Отправляем всю историю через новый метод chatWithHistory
                return ollamaClient.chatWithHistory(selectedModel, generalChatHistory);
            }
        };

        chatTask.setOnSucceeded(e -> {
            if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(false);
            String response = chatTask.getValue();

            // 4. Добавляем ответ ассистента в историю с явным указанием модели,
            // чтобы при смене модели новый ИИ понимал, кто именно давал предыдущий ответ
            String historyContent = "[Модель: " + selectedModel + "]\n" + response;
            generalChatHistory.add(new ChatMessage("assistant", historyContent));

            // 5. Выводим чистый ответ в UI (без служебного префикса)
            appendGeneralChatMessage("ИИ (" + selectedModel + ")", response);
        });

        chatTask.setOnFailed(e -> {
            if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(false);
            appendGeneralChatMessage("Система", "❌ **Ошибка взаимодействия с моделью.**");
        });

        Thread thread = new Thread(chatTask);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Сборка накопленного контекста переписки в единый промпт
     */
    private String buildPromptWithHistory() {
        StringBuilder sb = new StringBuilder();
        for (ChatMessage msg : generalChatHistory) {
            if ("user".equalsIgnoreCase(msg.getRole())) {
                sb.append("User: ").append(msg.getContent()).append("\n\n");
            } else {
                sb.append("Assistant: ").append(msg.getContent()).append("\n\n");
            }
        }
        sb.append("Assistant: ");
        return sb.toString();
    }

    private void handleSelectAllToggle() {
        TreeItem<File> root = fileTreeView.getRoot();
        if (root instanceof CheckBoxTreeItem<File> rootItem) {
            setSubtreeSelection(rootItem, selectAllCheckBox.isSelected());
        }
    }

    private void setSubtreeSelection(CheckBoxTreeItem<File> item, boolean select) {
        if (item == null) return;
        item.setSelected(select);
        for (TreeItem<File> child : item.getChildren()) {
            if (child instanceof CheckBoxTreeItem<File> childCheckBoxItem) {
                setSubtreeSelection(childCheckBoxItem, select);
            }
        }
    }

    private void handleSelectFolderClick() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом");
        Stage stage = (Stage) selectFolderButton.getScene().getWindow();
        File folder = directoryChooser.showDialog(stage);

        if (folder != null && folder.exists()) {
            this.selectedProjectFolder = folder;
            selectAllCheckBox.setSelected(true);
            buildFileTree(folder);
            scanButton.setDisable(false);
            appendMessageToChatHtml("Система", "📁 Загружен проект: `" + folder.getName() + "`.");
        }
    }

    private void handleClearProjectClick() {
        selectedProjectFolder = null;
        scannedFiles.clear();
        fileTreeView.setRoot(null);
        vulnerabilitiesTable.getItems().clear();
        scanButton.setDisable(true);
        resetChatHtml();
        resetGeneralChatHtml();
        generalChatHistory.clear();
        appendMessageToChatHtml("Система", "🧹 Проект и результаты анализа очищены.");
    }

    private void buildFileTree(File rootFolder) {
        CheckBoxTreeItem<File> rootItem = createTreeItem(rootFolder);
        rootItem.setExpanded(true);
        fileTreeView.setRoot(rootItem);
        fileTreeView.setShowRoot(true);
    }

    private CheckBoxTreeItem<File> createTreeItem(File file) {
        CheckBoxTreeItem<File> item = new CheckBoxTreeItem<>(file);
        item.setSelected(selectAllCheckBox.isSelected());

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

    private void handleStartScanClick() {
        if (fileTreeView.getRoot() == null) return;

        List<File> selectedFiles = new ArrayList<>();
        collectSelectedFiles((CheckBoxTreeItem<File>) fileTreeView.getRoot(), selectedFiles);

        if (selectedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Вы не выбрали ни одного файла!");
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
            fileTreeView.refresh();
            appendMessageToChatHtml("Система", "✅ **Анализ завершен!** Просканировано файлов: " + scannedFiles.size());
        });

        scanTask.setOnFailed(e -> {
            scanButton.setDisable(false);
            selectFolderButton.setDisable(false);
            scanButton.setText("🚀 Запустить анализ выбранных");
            appendMessageToChatHtml("Система", "❌ **Ошибка во время анализа.**");
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
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "PDF-отчет успешно сохранен!");
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

    private String getBaseCss() {
        return "<style>"
                + "body { font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 10px; padding: 0; }"
                + ".msg-card { background: #ffffff; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }"
                + ".sender { font-weight: bold; font-size: 12px; color: #34495e; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }"
                + "p { margin: 4px 0; color: #2c3e50; font-size: 13px; line-height: 1.5; }"
                + "code { background: #eef2f7; color: #c0392b; padding: 2px 5px; border-radius: 4px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }"
                + "pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }"
                + "pre code { background: none; color: #d4d4d4; padding: 0; }"
                + "h3 { color: #c0392b; margin-top: 0; font-size: 15px; }"
                + "h4 { color: #2c3e50; margin: 8px 0 4px 0; font-size: 13px; }"
                + "</style>";
    }

    private void resetChatHtml() {
        chatHistoryHtml.setLength(0);
        chatHistoryHtml.append("<!DOCTYPE html><html><head>").append(getBaseCss()).append("</head><body>");
        renderHtml(chatWebView, chatHistoryHtml);
    }

    private void resetGeneralChatHtml() {
        generalChatHtml.setLength(0);
        generalChatHtml.append("<!DOCTYPE html><html><head>").append(getBaseCss()).append("</head><body>");
        renderHtml(generalChatWebView, generalChatHtml);
    }

    private void appendMessageToChatHtml(String sender, String markdownText) {
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));
        chatHistoryHtml.append("<div class='msg-card'>")
                .append("<div class='sender'>").append(sender).append("</div>")
                .append(htmlContent)
                .append("</div>");
        renderHtml(chatWebView, chatHistoryHtml);
    }

    private void appendGeneralChatMessage(String sender, String markdownText) {
        if (generalChatWebView == null) return;
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));
        generalChatHtml.append("<div class='msg-card'>")
                .append("<div class='sender'>").append(sender).append("</div>")
                .append(htmlContent)
                .append("</div>");
        renderHtml(generalChatWebView, generalChatHtml);
    }

    private void renderHtml(WebView webView, StringBuilder htmlBuffer) {
        if (webView == null) return;
        String fullHtml = htmlBuffer.toString() + "<script>window.scrollTo(0, document.body.scrollHeight);</script></body></html>";
        Platform.runLater(() -> webView.getEngine().loadContent(fullHtml));
    }
}