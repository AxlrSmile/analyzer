package com.analyzer.ui.controller;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.AgentService;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.ai.OllamaClient.ChatMessage;
import com.analyzer.service.fix.FileFixService;
import com.analyzer.service.experiment.ScanExportService;
import com.analyzer.service.parser.CodeParser;
import com.analyzer.service.parser.FileAnalyzer;
import com.analyzer.service.report.PdfReportService;
import com.analyzer.service.scanner.ProjectScanner;
import com.analyzer.service.scanner.UnifiedScanService;
import com.analyzer.service.sast.SemgrepReportService;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import com.analyzer.domain.model.BenchmarkResult;
import com.analyzer.service.benchmark.BenchmarkService;

@Component
public class MainController {

    // ==========================================
    // Вкладка 1: Анализ безопасности проекта
    // ==========================================
    @FXML private Button selectFolderButton;
    @FXML private CheckBox selectAllCheckBox;
    @FXML private Button clearButton;
    @FXML private Button scanButton;
    @FXML private Button exportPdfButton;
    @FXML private Button exportResultsButton;
    @FXML private Button importSemgrepButton;
    @FXML private Button pasteCodeButton;
    @FXML private Button fixAllButton;
    @FXML private Button fixCurrentFileButton;

    // Выбор модели для сканирования (поддерживает оба возможных fx:id из разметки)
    @FXML private ComboBox<String> scanModelComboBox;
    @FXML private ComboBox<String> modelComboBox;

    @FXML private TreeView<File> fileTreeView;
    @FXML private TableView<Vulnerability> vulnerabilitiesTable;
    @FXML private TableColumn<Vulnerability, String> titleColumn;
    @FXML private TableColumn<Vulnerability, String> severityColumn;
    @FXML private TableColumn<Vulnerability, String> linesColumn;
    @FXML private TableColumn<Vulnerability, String> validationColumn;

    @FXML private WebView chatWebView;
    @FXML private TextField promptInputField;
    @FXML private Button sendPromptButton;

    // ==========================================
    // Вкладка 2: Свободный чат с ИИ
    // ==========================================
    @FXML private ComboBox<String> chatModelComboBox;
    @FXML private Button refreshModelsButton;
    @FXML private WebView generalChatWebView;
    @FXML private TextField generalChatPromptInput;
    @FXML private Button sendGeneralChatPromptButton;
    @FXML private Button clearGeneralChatButton;

    // ==========================================
    // Вкладка 3: ИИ-Агент Генерации Проекта
    // ==========================================
    @FXML private TextField agentWorkDirInput;
    @FXML private Button agentSelectFolderButton;
    @FXML private ComboBox<String> agentModelComboBox;
    @FXML private TextArea agentTaskPromptInput;
    @FXML private Button agentStartButton;
    @FXML private WebView agentLogWebView;

    // ==========================================
    // Вкладка 4: Сравнительный бенчмаркинг
    // ==========================================
    @FXML private Button selectBenchmarkFolderButton;
    @FXML private Label benchmarkFolderLabel;
    @FXML private Button startBenchmarkButton;
    @FXML private TableView<BenchmarkResult> benchmarkTable;
    @FXML private TableColumn<BenchmarkResult, String> bmModelCol;
    @FXML private TableColumn<BenchmarkResult, Integer> bmFilesCol;
    @FXML private TableColumn<BenchmarkResult, Integer> bmTpCol;
    @FXML private TableColumn<BenchmarkResult, Integer> bmFpCol;
    @FXML private TableColumn<BenchmarkResult, Integer> bmTnCol;
    @FXML private TableColumn<BenchmarkResult, Integer> bmFnCol;
    @FXML private TableColumn<BenchmarkResult, String> bmPrecisionCol;
    @FXML private TableColumn<BenchmarkResult, String> bmRecallCol;
    @FXML private TableColumn<BenchmarkResult, String> bmF1Col;
    @FXML private TableColumn<BenchmarkResult, String> bmTotalTimeCol;
    @FXML private TableColumn<BenchmarkResult, String> bmAvgTimeCol;

    private final BenchmarkService benchmarkService;
    private File benchmarkFolder;

    // ==========================================
    // Сервисы Spring
    // ==========================================
    private final FileAnalyzer fileAnalyzer;
    private final CodeParser codeParser;
    private final OllamaClient ollamaClient;
    private final PdfReportService pdfReportService;
    private final FileFixService fileFixService;
    private final AgentService agentService;
    private final SecurityScannerAgent securityScannerAgent;
    private final SemgrepReportService semgrepReportService;
    private final UnifiedScanService unifiedScanService;
    private final ScanExportService scanExportService;
    private String lastScanModel;
    private UnifiedScanService.ScanResult lastScanResult;

    // ==========================================
    // Внутренние состояния и буферы
    // ==========================================
    private final ObservableList<SourceFile> scannedFiles = FXCollections.observableArrayList();

    private final Parser markdownParser = Parser.builder().build();
    private final HtmlRenderer htmlRenderer = HtmlRenderer.builder().build();

    // HTML-буферы для рендеринга WebViews
    private final StringBuilder chatHistoryHtml = new StringBuilder();
    private final StringBuilder generalChatHtml = new StringBuilder();
    private final StringBuilder agentLogHtml = new StringBuilder();

    // Единая история сообщений общего чата
    private final List<ChatMessage> generalChatHistory = new ArrayList<>();

    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser,
                          OllamaClient ollamaClient,
                          PdfReportService pdfReportService,
                          FileFixService fileFixService,
                          AgentService agentService,
                          SecurityScannerAgent securityScannerAgent,
                          BenchmarkService benchmarkService,
                          SemgrepReportService semgrepReportService,
                          UnifiedScanService unifiedScanService,
                          ScanExportService scanExportService) {
        this.fileAnalyzer = fileAnalyzer;
        this.codeParser = codeParser;
        this.ollamaClient = ollamaClient;
        this.pdfReportService = pdfReportService;
        this.fileFixService = fileFixService;
        this.agentService = agentService;
        this.securityScannerAgent = securityScannerAgent;
        this.benchmarkService = benchmarkService;
        this.semgrepReportService = semgrepReportService;
        this.unifiedScanService = unifiedScanService;
        this.scanExportService = scanExportService;
    }

    @FXML
    public void initialize() {
        // 1. Настройка таблицы уязвимостей
        if (titleColumn != null) titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        if (severityColumn != null) severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        if (linesColumn != null) linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));
        if (validationColumn != null) validationColumn.setCellValueFactory(
                new PropertyValueFactory<>("validationStatusLabel"));

        // 2. Оформление дерева файлов с чекбоксами и статусами
        if (fileTreeView != null) {
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
        }

        if (vulnerabilitiesTable != null) {
            vulnerabilitiesTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
                if (newSelection != null) {
                    showVulnerabilityDetails(newSelection);
                }
            });
        }

        // 4. Назначение обработчиков событий для первой вкладки
        if (selectAllCheckBox != null) selectAllCheckBox.setOnAction(event -> handleSelectAllToggle());
        if (selectFolderButton != null) selectFolderButton.setOnAction(event -> handleSelectFolderClick());
        if (clearButton != null) clearButton.setOnAction(event -> handleClearProjectClick());
        if (scanButton != null) scanButton.setOnAction(event -> handleStartScanClick());
        if (pasteCodeButton != null) pasteCodeButton.setOnAction(event -> handlePasteAndAnalyzeCode());
        if (exportPdfButton != null) exportPdfButton.setOnAction(event -> handleExportPdfClick());
        if (exportResultsButton != null) exportResultsButton.setOnAction(event -> handleExportResultsClick());
        if (importSemgrepButton != null) importSemgrepButton.setOnAction(event -> handleImportSemgrepClick());
        if (sendPromptButton != null) sendPromptButton.setOnAction(event -> handleSendPromptClick());
        if (promptInputField != null) promptInputField.setOnAction(event -> handleSendPromptClick());
        if (fixCurrentFileButton != null) fixCurrentFileButton.setOnAction(event -> handleFixCurrentFileClick());
        if (fixAllButton != null) fixAllButton.setOnAction(event -> handleFixAllClick());

        // 5. Назначение обработчиков событий для свободного чата
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
            if (pasteCodeButton != null && pasteCodeButton.getScene() != null) {
                pasteCodeButton.getScene().getAccelerators().put(
                        new KeyCodeCombination(KeyCode.V, KeyCombination.CONTROL_DOWN),
                        this::handlePasteAndAnalyzeCode
                );
            }
        });

        // Настройка колонок таблицы бенчмарка
        if (benchmarkTable != null) {
            bmModelCol.setCellValueFactory(new PropertyValueFactory<>("modelName"));
            bmFilesCol.setCellValueFactory(new PropertyValueFactory<>("totalFiles"));
            bmTpCol.setCellValueFactory(new PropertyValueFactory<>("truePositives"));
            bmFpCol.setCellValueFactory(new PropertyValueFactory<>("falsePositives"));
            bmTnCol.setCellValueFactory(new PropertyValueFactory<>("trueNegatives"));
            bmFnCol.setCellValueFactory(new PropertyValueFactory<>("falseNegatives"));
            bmPrecisionCol.setCellValueFactory(new PropertyValueFactory<>("precisionFormatted"));
            bmRecallCol.setCellValueFactory(new PropertyValueFactory<>("recallFormatted"));
            bmF1Col.setCellValueFactory(new PropertyValueFactory<>("f1ScoreFormatted"));
            bmTotalTimeCol.setCellValueFactory(new PropertyValueFactory<>("totalTimeFormatted"));
            bmAvgTimeCol.setCellValueFactory(new PropertyValueFactory<>("avgTimeFormatted"));
        }

        // Сброс окон WebView и загрузка моделей
        resetChatHtml();
        resetGeneralChatHtml();
        resetAgentLogHtml();
        loadAvailableModels();
    }

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
                if (scanModelComboBox != null) {
                    scanModelComboBox.setItems(modelList);
                    scanModelComboBox.getSelectionModel().selectFirst();
                }
                if (modelComboBox != null) {
                    modelComboBox.setItems(modelList);
                    modelComboBox.getSelectionModel().selectFirst();
                }
                if (chatModelComboBox != null) {
                    chatModelComboBox.setItems(modelList);
                    chatModelComboBox.getSelectionModel().selectFirst();
                }
                if (agentModelComboBox != null) {
                    agentModelComboBox.setItems(modelList);
                    agentModelComboBox.getSelectionModel().selectFirst();
                }
            }
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Получить выбранную модель для вкладки сканирования
     */
    private String getSelectedScanModel() {
        if (scanModelComboBox != null && scanModelComboBox.getValue() != null && !scanModelComboBox.getValue().isBlank()) {
            return scanModelComboBox.getValue();
        }
        if (modelComboBox != null && modelComboBox.getValue() != null && !modelComboBox.getValue().isBlank()) {
            return modelComboBox.getValue();
        }
        return "qwen2.5-coder:7b";
    }

    // ==========================================
    // ЛОГИКА ВКЛАДКИ ИИ-АГЕНТА
    // ==========================================

    @FXML
    private void handleAgentSelectFolder() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите рабочую папку для создания проекта");

        Stage stage = (Stage) agentSelectFolderButton.getScene().getWindow();
        File folder = directoryChooser.showDialog(stage);

        if (folder != null) {
            agentWorkDirInput.setText(folder.getAbsolutePath());
        }
    }


    @FXML
    private void handleSelectBenchmarkFolder() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Выберите директорию с бенчмарк-файлами");
        Stage stage = (Stage) selectBenchmarkFolderButton.getScene().getWindow();
        File dir = chooser.showDialog(stage);
        if (dir != null) {
            benchmarkFolder = dir;
            benchmarkFolderLabel.setText(dir.getAbsolutePath());
        }
    }

    @FXML
    private void handleStartBenchmark() {
        if (benchmarkFolder == null || !benchmarkFolder.exists()) {
            new Alert(Alert.AlertType.WARNING, "Сначала укажите папку с тестовыми файлами!").showAndWait();
            return;
        }

        File[] files = benchmarkFolder.listFiles(f -> f.isFile() && !f.getName().startsWith("."));
        if (files == null || files.length == 0) {
            new Alert(Alert.AlertType.WARNING, "В выбранной папке нет подходящих файлов!").showAndWait();
            return;
        }

        List<String> models = ollamaClient.getAvailableModels();
        if (models.isEmpty()) {
            new Alert(Alert.AlertType.WARNING, "В Ollama не найдено активных моделей!").showAndWait();
            return;
        }

        startBenchmarkButton.setDisable(true);
        benchmarkTable.getItems().clear();

        Task<List<BenchmarkResult>> task = new Task<>() {
            @Override
            protected List<BenchmarkResult> call() {
                return benchmarkService.runBenchmark(List.of(files), models, System.out::println);
            }
        };

        task.setOnSucceeded(e -> {
            startBenchmarkButton.setDisable(false);
            benchmarkTable.setItems(FXCollections.observableArrayList(task.getValue()));
        });

        task.setOnFailed(e -> {
            startBenchmarkButton.setDisable(false);
            new Alert(Alert.AlertType.ERROR, "Ошибка выполнения бенчмарка: " + task.getException().getMessage()).showAndWait();
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    private void handleAgentStartExecution() {
        String folderPath = agentWorkDirInput.getText().trim();
        String prompt = agentTaskPromptInput.getText().trim();
        String selectedModel = (agentModelComboBox != null) ? agentModelComboBox.getValue() : null;

        if (folderPath.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Пожалуйста, выберите рабочую папку!");
            alert.showAndWait();
            return;
        }

        if (prompt.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Пожалуйста, опишите задачу для агента!");
            alert.showAndWait();
            return;
        }

        if (selectedModel == null || selectedModel.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Пожалуйста, выберите модель для генерации!");
            alert.showAndWait();
            return;
        }

        File targetDir = new File(folderPath);
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }

        agentStartButton.setDisable(true);
        resetAgentLogHtml();

        Task<Void> agentTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                agentService.executeAgentTask(
                        targetDir,
                        prompt,
                        selectedModel,
                        logMessage -> Platform.runLater(() -> appendAgentLog(logMessage))
                );
                return null;
            }
        };

        agentTask.setOnSucceeded(e -> agentStartButton.setDisable(false));
        agentTask.setOnFailed(e -> {
            agentStartButton.setDisable(false);
            appendAgentLog("❌ **Произошла ошибка при работе агента:** " + agentTask.getException().getMessage());
        });

        Thread thread = new Thread(agentTask);
        thread.setDaemon(true);
        thread.start();
    }

    // ==========================================
    // ЛОГИКА СВОБОДНОГО ЧАТА
    // ==========================================

    @FXML
    private void handleClearGeneralChat() {
        generalChatHistory.clear();
        resetGeneralChatHtml();
        appendGeneralChatMessage("Система", "🧹 **Чат и контекст диалога успешно сброшены.**");
    }

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

        appendGeneralChatMessage("Вы", prompt);
        generalChatHistory.add(new ChatMessage("user", prompt));

        generalChatPromptInput.clear();
        if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(true);

        Task<String> chatTask = new Task<>() {
            @Override
            protected String call() {
                return ollamaClient.chatWithHistory(selectedModel, generalChatHistory);
            }
        };

        chatTask.setOnSucceeded(e -> {
            if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(false);
            String response = chatTask.getValue();

            generalChatHistory.add(new ChatMessage("assistant", response));
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

    // ==========================================
    // ЛОГИКА АНАЛИЗА КОДА И СКАНЕРА
    // ==========================================

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
            selectAllCheckBox.setSelected(true);
            lastScanResult = null;
            buildFileTree(folder);
            scanButton.setDisable(false);
            appendMessageToChatHtml("Система", "📁 Загружен проект: `" + folder.getName() + "`.");
        }
    }

    private void handleClearProjectClick() {
        scannedFiles.clear();
        lastScanResult = null;
        lastScanModel = null;
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
                    String name = child.getName().toLowerCase();

                    // Фильтруем служебные директории и бинарные классы
                    if (!name.startsWith(".")
                            && !name.equalsIgnoreCase("target")
                            && !name.equalsIgnoreCase("build")
                            && !name.equalsIgnoreCase("out")
                            && !name.equalsIgnoreCase("bin")
                            && !name.endsWith(".class")) {
                        item.getChildren().add(createTreeItem(child));
                    }
                }
            }
        }
        return item;
    }

    private void handleStartScanClick() {
        if (fileTreeView == null || fileTreeView.getRoot() == null) return;
        File projectFolder = fileTreeView.getRoot().getValue();
        if (projectFolder == null || !projectFolder.isDirectory()) {
            new Alert(Alert.AlertType.WARNING, "Сначала выберите папку проекта.").showAndWait();
            return;
        }

        List<File> selectedFiles = new ArrayList<>();
        collectSelectedFiles((CheckBoxTreeItem<File>) fileTreeView.getRoot(), selectedFiles);
        if (selectedFiles.isEmpty()) {
            new Alert(Alert.AlertType.WARNING, "Вы не выбрали ни одного файла!").showAndWait();
            return;
        }
        String targetModel = getSelectedScanModel();
        scannedFiles.clear();
        lastScanModel = targetModel;
        lastScanResult = null;
        vulnerabilitiesTable.getItems().clear();
        resetChatHtml();
        scanButton.setDisable(true);
        selectFolderButton.setDisable(true);
        if (clearButton != null) clearButton.setDisable(true);
        if (importSemgrepButton != null) importSemgrepButton.setDisable(true);
        scanButton.setText("LLM + Semgrep: идёт анализ...");
        appendMessageToChatHtml("Система", "🔍 **Запущены Semgrep и LLM.** Модель: `"
                + targetModel + "`. Исходный код не запускается; Semgrep работает в отдельном процессе.");

        Task<UnifiedScanService.ScanResult> task = new Task<>() {
            @Override
            protected UnifiedScanService.ScanResult call() throws Exception {
                return unifiedScanService.scan(projectFolder.toPath(), selectedFiles, targetModel);
            }
        };
        task.setOnSucceeded(e -> {
            finishUnifiedScan();
            UnifiedScanService.ScanResult result = task.getValue();
            lastScanResult = result;
            scannedFiles.setAll(result.files());
            fileTreeView.refresh();
            TreeItem<File> selection = fileTreeView.getSelectionModel().getSelectedItem();
            if (selection != null && selection.getValue() != null && selection.getValue().isFile()) {
                scannedFiles.stream().filter(sf -> sf.getPath() != null
                        && sf.getPath().toAbsolutePath().normalize().equals(
                                selection.getValue().toPath().toAbsolutePath().normalize()))
                        .findFirst().ifPresent(this::showVulnerabilitiesForFile);
            }
            String status = result.sastCompleted() && result.failedByLlm() == 0 && result.partialByLlm() == 0
                    && result.diagnostics().isEmpty() ? "✅ Проверка завершена" : "⚠️ Проверка завершена с ограничениями";
            StringBuilder summary = new StringBuilder(status)
                    .append(". Файлов загружено: ").append(result.files().size())
                    .append(". LLM успешно проверила: ").append(result.analyzedByLlm())
                    .append(", неполных LLM: ").append(result.partialByLlm())
                    .append(", ошибок LLM: ").append(result.failedByLlm())
                    .append(". Semgrep: ").append(result.sastCompleted()
                            ? result.sastFindings() + " срабатываний" : "не выполнен")
                    .append(". ИИ-ревью SAST: ").append(result.aiReviewed())
                    .append(" оценено, ").append(result.aiReviewFailed()).append(" ошибок, ")
                    .append(result.aiReviewSkipped()).append(" пропущено")
                    .append(". Возможных совпадений строк: ").append(result.possibleOverlaps())
                    .append(". Пропущено файлов: ").append(result.skippedTargets())
                    .append(". Несопоставленных SAST-находок: ").append(result.unrelatedFindings())
                    .append(".\n\n**Важно:** совпадение строк не подтверждает уязвимость; отсутствие находок не гарантирует безопасность.");
            for (String diagnostic : result.diagnostics()) {
                summary.append("\n\n⚠️ ").append(escapeHtml(diagnostic));
            }
            appendMessageToChatHtml("Система", summary.toString());
        });
        task.setOnFailed(e -> {
            finishUnifiedScan();
            Throwable error = task.getException();
            appendMessageToChatHtml("Система", "❌ **Ошибка анализа:** "
                    + (error == null ? "неизвестная ошибка" : escapeHtml(error.getMessage()))
                    + "\n\nРезультат нельзя интерпретировать как отсутствие уязвимостей.");
        });
        Thread thread = new Thread(task, "unified-security-scan");
        thread.setDaemon(true);
        thread.start();
    }

    private void finishUnifiedScan() {
        scanButton.setDisable(false);
        selectFolderButton.setDisable(false);
        if (clearButton != null) clearButton.setDisable(false);
        if (importSemgrepButton != null) importSemgrepButton.setDisable(false);
        scanButton.setText("🚀 Запустить анализ выбранных");
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
                "### ⚠️ %s\n\n**Критичность:** `%s`  \n**Строки:** `%s`  \n**Статус:** %s\n\n**Пояснение:** %s\n\n**ИИ-ревью:** %s\n\n**Обоснование ИИ:** %s\n\n#### Описание:\n%s\n\n#### Рекомендация:\n%s",
                escapeHtml(vulnerability.getTitle()), escapeHtml(vulnerability.getSeverity()),
                escapeHtml(vulnerability.getLineRange()),
                escapeHtml(vulnerability.getValidationStatusLabel()),
                escapeHtml(vulnerability.getValidationNote()),
                escapeHtml(vulnerability.getAiReviewStatusLabel()),
                escapeHtml(vulnerability.getAiReviewNote()),
                escapeHtml(vulnerability.getDescription()), escapeHtml(vulnerability.getRecommendation())
        );
        if (vulnerability.getCwe() != null) {
            markdownReport += "\n\n**CWE:** `" + escapeHtml(vulnerability.getCwe()) + "`";
        }
        if (vulnerability.getCweAdvisorStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getCweAdvisorStatus())) {
            markdownReport += "\n\n**Оценка CWE по коду:** `" + escapeHtml(vulnerability.getCweAdvisorStatus()) + "`";
            if (vulnerability.getCweSuggestion() != null) {
                markdownReport += "\n\n**Предлагаемая категория (не диагноз):** `"
                        + escapeHtml(vulnerability.getCweSuggestion()) + "`";
            }
            if (vulnerability.getCweAdvisorNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getCweAdvisorNote());
            }
        }
        if (vulnerability.getSemanticStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getSemanticStatus())) {
            markdownReport += "\n\n**Проверка CWE:** `" + escapeHtml(vulnerability.getSemanticStatus()) + "`";
            if (vulnerability.getSemanticNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getSemanticNote());
            }
        }
        if (vulnerability.getMechanismStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getMechanismStatus())) {
            markdownReport += "\n\n**Проверка механизма:** `" + escapeHtml(vulnerability.getMechanismStatus()) + "`";
            if (vulnerability.getMechanismNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getMechanismNote());
            }
        }
        if (vulnerability.getEvidence() != null) {
            markdownReport += "\n\n**Цитата исходного кода (LLM):** `"
                    + escapeHtml(vulnerability.getEvidence().replace("`", "'")) + "`";
        }
        if (vulnerability.getModelOutputStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getModelOutputStatus())) {
            markdownReport += "\n\n**Качество ответа LLM:** `"
                    + escapeHtml(vulnerability.getModelOutputStatus()) + "`";
            if (vulnerability.getModelOutputNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getModelOutputNote());
            }
        }
        if (vulnerability.getSourceExcerpt() != null) {
            markdownReport += "\n\n**Исходная строка (для ручной сверки, не доказательство):** `"
                    + escapeHtml(vulnerability.getSourceExcerpt().replace("`", "'")) + "`";
        }
        appendMessageToChatHtml("ИИ-Анализатор", markdownReport);
    }

    /**
     * Imports a previously generated Semgrep JSON report for the selected project.
     * Import is deliberately read-only: it never invokes external code or applies fixes.
     */
    private void handleImportSemgrepClick() {
        if (fileTreeView == null || fileTreeView.getRoot() == null) {
            new Alert(Alert.AlertType.WARNING, "Сначала выберите папку проекта.").showAndWait();
            return;
        }
        File projectFolder = fileTreeView.getRoot().getValue();
        if (projectFolder == null || !projectFolder.isDirectory()) {
            new Alert(Alert.AlertType.WARNING, "Сначала выберите папку проекта.").showAndWait();
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Открыть JSON-отчёт Semgrep");
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("JSON files (*.json)", "*.json"));
        File preferred = new File(projectFolder, "semgrep-results.json");
        if (preferred.isFile()) chooser.setInitialFileName(preferred.getName());
        File file = chooser.showOpenDialog((Stage) importSemgrepButton.getScene().getWindow());
        if (file == null) return;

        final SemgrepReportService.Report report;
        try {
            report = semgrepReportService.read(file.toPath());
        } catch (IOException ex) {
            new Alert(Alert.AlertType.ERROR, "Не удалось прочитать Semgrep JSON: " + ex.getMessage()).showAndWait();
            return;
        }
        // Validate all source paths before updating the UI, to avoid half-imports.
        record Entry(Path file, SemgrepReportService.Finding finding) { }
        List<Entry> entries = new ArrayList<>();
        int missing = 0;
        for (var finding : report.findings()) {
            try {
                entries.add(new Entry(
                        semgrepReportService.resolveInProject(projectFolder.toPath(), finding.path()), finding));
            } catch (IOException ex) {
                missing++;
            }
        }
        // Replace previous Semgrep findings. Any old LLM/SAST overlap label
        // is invalid once the SAST report changes.
        lastScanResult = null;
        lastScanModel = null;
        for (SourceFile sf : scannedFiles) {
            sf.getVulnerabilities().removeIf(v -> "SAST_REPORTED".equals(v.getValidationStatus()));
            for (Vulnerability v : sf.getVulnerabilities()) {
                if ("POSSIBLE_SAST_MATCH".equals(v.getValidationStatus())) {
                    v.setValidationStatus("LOCATION_CHECKED");
                    v.setValidationNote("Импортирован новый отчёт Semgrep; старое совпадение сброшено. "
                            + "Проверка координат LLM не подтверждает уязвимость.");
                }
            }
        }
        int imported = 0;
        for (Entry entry : entries) {
            try {
                SourceFile sf = scannedFiles.stream()
                        .filter(existing -> existing.getPath() != null
                                && existing.getPath().toAbsolutePath().normalize().equals(entry.file()))
                        .findFirst().orElse(null);
                if (sf == null) {
                    String content = Files.readString(entry.file());
                    sf = new SourceFile(entry.file().getFileName().toString(), entry.file(),
                            projectFolder.toPath().toRealPath().relativize(entry.file()).toString(),
                            content.lines().count(), content);
                    scannedFiles.add(sf);
                }
                sf.getVulnerabilities().add(semgrepReportService.toVulnerability(entry.finding()));
                imported++;
            } catch (IOException ex) {
                missing++;
            }
        }
        fileTreeView.refresh();
        TreeItem<File> selected = fileTreeView.getSelectionModel().getSelectedItem();
        if (selected != null && selected.getValue() != null && selected.getValue().isFile()) {
            File selectedFile = selected.getValue();
            scannedFiles.stream().filter(sf -> sf.getPath() != null
                    && sf.getPath().toAbsolutePath().normalize().equals(selectedFile.toPath().toAbsolutePath().normalize()))
                    .findFirst().ifPresent(this::showVulnerabilitiesForFile);
        }
        String summary = "Semgrep: в отчёте " + report.findings().size() + " срабатываний, "
                + "импортировано " + imported + ", не сопоставлено с проектом " + missing
                + ", диагностических ошибок " + report.errors().size() + ".";
        appendMessageToChatHtml("Система", summary + "\n\n**Внимание:** Семгреп-находки не подтверждают "
                + "эксплуатируемость; ноль находок не гарантирует отсутствие уязвимостей.");
        if (missing > 0 || report.hasErrors()) {
            new Alert(Alert.AlertType.WARNING, summary + "\nПроверьте полноту отчёта и пути к файлам.").showAndWait();
        } else {
            new Alert(Alert.AlertType.INFORMATION, summary).showAndWait();
        }
    }

    private static String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private void handleExportResultsClick() {
        if (scannedFiles.isEmpty()) {
            new Alert(Alert.AlertType.WARNING, "Сначала просканируйте проект или импортируйте отчёт.").showAndWait();
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Экспорт необработанных результатов (возможны фрагменты секретов)");
        FileChooser.ExtensionFilter json = new FileChooser.ExtensionFilter("JSON (*.json)", "*.json");
        FileChooser.ExtensionFilter csv = new FileChooser.ExtensionFilter("CSV (*.csv)", "*.csv");
        chooser.getExtensionFilters().addAll(json, csv);
        chooser.setSelectedExtensionFilter(json);
        chooser.setInitialFileName("security-findings");
        File selected = chooser.showSaveDialog((Stage) exportResultsButton.getScene().getWindow());
        if (selected == null) return;
        String name = selected.getName().toLowerCase(java.util.Locale.ROOT);
        boolean asCsv = name.endsWith(".csv") || (!name.endsWith(".json")
                && chooser.getSelectedExtensionFilter() == csv);
        Path destination = selected.toPath();
        if (!name.endsWith(".csv") && !name.endsWith(".json")) {
            destination = destination.resolveSibling(selected.getName() + (asCsv ? ".csv" : ".json"));
        }
        try {
            if (asCsv) scanExportService.writeCsv(destination, List.copyOf(scannedFiles), lastScanResult);
            else scanExportService.writeJson(destination, List.copyOf(scannedFiles), lastScanResult, lastScanModel);
            new Alert(Alert.AlertType.INFORMATION, "Экспорт сохранён. Не публикуйте файл без проверки секретов.")
                    .showAndWait();
        } catch (IOException ex) {
            new Alert(Alert.AlertType.ERROR, "Ошибка экспорта: " + ex.getMessage()).showAndWait();
        }
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
                String coverage = lastScanResult == null ?
                        "Состояние автоматической проверки неизвестно (возможен ручной импорт)." :
                        "LLM: " + lastScanResult.analyzedByLlm() + " файлов успешно, "
                        + lastScanResult.failedByLlm() + " ошибок, "
                        + lastScanResult.partialByLlm() + " неполных; Semgrep: "
                        + (lastScanResult.sastCompleted() ? "запущен" : "не выполнен")
                        + "; пропущено файлов: " + lastScanResult.skippedTargets()
                        + "; диагностик: " + lastScanResult.diagnostics().size() + ".";
                pdfReportService.generatePdfReport(scannedFiles, saveFile.getAbsolutePath(), coverage);
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
        textArea.setPromptText("Вставьте фрагмент кода (C, C++, Java, Python, Go)...");
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

            String targetModel = getSelectedScanModel();
            String snippetName = "Snippet_" + System.currentTimeMillis();
            SourceFile virtualFile = new SourceFile(snippetName, null, "Unknown", codeContent.getBytes().length, codeContent);

            pasteCodeButton.setDisable(true);
            appendMessageToChatHtml("Система", "⏳ *Выполняется экспресс-анализ моделью `" + targetModel + "`...*");

            Task<List<Vulnerability>> analyzeTask = new Task<>() {
                @Override
                protected List<Vulnerability> call() throws Exception {
                    return securityScannerAgent.scanChunk(codeContent, "Unknown", targetModel);
                }
            };

            analyzeTask.setOnSucceeded(e -> {
                pasteCodeButton.setDisable(false);
                List<Vulnerability> vulnerabilities = analyzeTask.getValue();
                virtualFile.setVulnerabilities(vulnerabilities);
                scannedFiles.add(virtualFile);

                if (vulnerabilities.isEmpty()) {
                    appendMessageToChatHtml("ИИ-Консультант (" + targetModel + ")", "✅ **Уязвимости во фрагменте кода не обнаружены!**");
                } else {
                    appendMessageToChatHtml("ИИ-Консультант (" + targetModel + ")", "⚠️ **Анализ завершен!** Обнаружено уязвимостей: **" + vulnerabilities.size() + "**.");
                }
            });

            analyzeTask.setOnFailed(e -> {
                pasteCodeButton.setDisable(false);
                appendMessageToChatHtml("Система", "❌ **Ошибка во время анализа фрагмента кода:** " + analyzeTask.getException().getMessage());
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

        String targetModel = getSelectedScanModel();
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
            appendMessageToChatHtml("ИИ-Консультант (" + targetModel + ")", chatTask.getValue());
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

        String targetModel = getSelectedScanModel();
        fixCurrentFileButton.setDisable(true);
        appendMessageToChatHtml("Система", "⏳ *Модель `" + targetModel + "` формирует исправленный вариант файла " + selectedFile.getName() + "...*");

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
                appendMessageToChatHtml("ИИ-Консультант (" + targetModel + ")", "✅ **Исправленный вариант сохранен в файл:** `" + createdFileName + "`\n\n```\n" + fixedCode + "\n```");
            } catch (Exception ex) {
                fixCurrentFileButton.setDisable(false);
                appendMessageToChatHtml("Система", "❌ **Ошибка сохранения файла:** " + ex.getMessage());
            }
        });

        fixTask.setOnFailed(e -> {
            fixCurrentFileButton.setDisable(false);
            appendMessageToChatHtml("Система", "❌ **Ошибка генерации исправления ИИ:** " + fixTask.getException().getMessage());
        });

        Thread thread = new Thread(fixTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void handleFixAllClick() {
        if (scannedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Сначала просканируйте проект!");
            alert.showAndWait();
            return;
        }

        String targetModel = getSelectedScanModel();
        fixAllButton.setDisable(true);
        appendMessageToChatHtml("Система", "⏳ *Запущена пакетная генерация исправлений моделью `" + targetModel + "`...*");

        Task<Void> fixAllTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                for (SourceFile sf : scannedFiles) {
                    if (sf.getVulnerabilities() != null && !sf.getVulnerabilities().isEmpty()) {
                        try {
                            String fixedCode = ollamaClient.fixSourceFile(sf);
                            String savedPath = fileFixService.saveFixedVersionAsTxt(sf, fixedCode);
                            Platform.runLater(() -> appendMessageToChatHtml("Система", "✅ Исправлен (" + targetModel + "): `" + sf.getName() + "` -> `" + savedPath + "`"));
                        } catch (Exception ex) {
                            Platform.runLater(() -> appendMessageToChatHtml("Система", "❌ Ошибка при исправлении `" + sf.getName() + "`: " + ex.getMessage()));
                        }
                    }
                }
                return null;
            }
        };

        fixAllTask.setOnSucceeded(e -> {
            fixAllButton.setDisable(false);
            appendMessageToChatHtml("Система", "🎉 **Пакетное исправление успешно завершено!**");
        });

        fixAllTask.setOnFailed(e -> {
            fixAllButton.setDisable(false);
            appendMessageToChatHtml("Система", "❌ **Ошибка при пакетном исправлении файлов:** " + fixAllTask.getException().getMessage());
        });

        Thread thread = new Thread(fixAllTask);
        thread.setDaemon(true);
        thread.start();
    }

    // ==========================================
    // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ HTML И WEBVIEW
    // ==========================================

    private void resetChatHtml() {
        chatHistoryHtml.setLength(0);
        chatHistoryHtml.append("<html><head><style>")
                .append("body { font-family: 'Segoe UI', sans-serif; margin: 10px; background-color: #f8f9fa; color: #333; }")
                .append("h3 { color: #2c3e50; }")
                .append("pre { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 5px; overflow-x: auto; }")
                .append("code { background: #eef; padding: 2px 4px; border-radius: 3px; font-family: Consolas, monospace; }")
                .append(".msg { margin-bottom: 12px; padding: 8px 12px; border-radius: 6px; }")
                .append(".user { background: #e3f2fd; border-left: 4px solid #2196f3; }")
                .append(".ai { background: #ffffff; border-left: 4px solid #4caf50; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }")
                .append(".system { background: #fff3e0; border-left: 4px solid #ff9800; }")
                .append("</style></head><body>");
        updateWebView(chatWebView, chatHistoryHtml);
    }

    private void resetGeneralChatHtml() {
        generalChatHtml.setLength(0);
        generalChatHtml.append("<html><head><style>")
                .append("body { font-family: 'Segoe UI', sans-serif; margin: 10px; background-color: #f8f9fa; color: #333; }")
                .append("pre { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 5px; overflow-x: auto; }")
                .append("code { background: #eef; padding: 2px 4px; border-radius: 3px; font-family: Consolas, monospace; }")
                .append(".msg { margin-bottom: 12px; padding: 8px 12px; border-radius: 6px; }")
                .append(".user { background: #e3f2fd; border-left: 4px solid #2196f3; }")
                .append(".ai { background: #ffffff; border-left: 4px solid #4caf50; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }")
                .append(".system { background: #fff3e0; border-left: 4px solid #ff9800; }")
                .append("</style></head><body>");
        updateWebView(generalChatWebView, generalChatHtml);
    }

    private void resetAgentLogHtml() {
        agentLogHtml.setLength(0);
        agentLogHtml.append("<html><head><style>")
                .append("body { font-family: 'Consolas', 'Courier New', monospace; margin: 10px; background-color: #1e1e1e; color: #d4d4d4; font-size: 13px; }")
                .append("pre { background: #2d2d2d; color: #9cdcfe; padding: 10px; border-radius: 5px; overflow-x: auto; }")
                .append("code { color: #ce9178; }")
                .append(".log { margin-bottom: 6px; line-height: 1.4; }")
                .append("</style></head><body>");
        updateWebView(agentLogWebView, agentLogHtml);
    }

    private void appendMessageToChatHtml(String sender, String markdownText) {
        String cssClass = sender.equals("Вы") ? "user" : (sender.equals("Система") ? "system" : "ai");
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));
        chatHistoryHtml.append("<div class='msg ").append(cssClass).append("'>")
                .append("<strong>").append(sender).append(":</strong><br/>")
                .append(htmlContent)
                .append("</div>");
        updateWebView(chatWebView, chatHistoryHtml);
    }

    private void appendGeneralChatMessage(String sender, String markdownText) {
        String cssClass = sender.equals("Вы") ? "user" : (sender.equals("Система") ? "system" : "ai");
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));
        generalChatHtml.append("<div class='msg ").append(cssClass).append("'>")
                .append("<strong>").append(sender).append(":</strong><br/>")
                .append(htmlContent)
                .append("</div>");
        updateWebView(generalChatWebView, generalChatHtml);
    }

    private void appendAgentLog(String markdownLog) {
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownLog));
        agentLogHtml.append("<div class='log'>").append(htmlContent).append("</div>");
        updateWebView(agentLogWebView, agentLogHtml);
    }

    private void updateWebView(WebView webView, StringBuilder htmlBuffer) {
        if (webView != null) {
            String content = htmlBuffer.toString() + "</body></html>";
            Platform.runLater(() -> webView.getEngine().loadContent(content));
        }
    }
}