package com.analyzer.ui.controller;

import javafx.scene.layout.VBox;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.AgentService;
import com.analyzer.service.agent.SecurityScannerAgent;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.ai.OllamaClient.ChatMessage;
import com.analyzer.service.fix.FixRecommendationAgent;
import com.analyzer.service.fix.FixReviewService;
import com.analyzer.service.fix.FixProposal;
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
import javafx.event.ActionEvent;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.CheckBoxTreeCell;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.*;
import javafx.scene.web.WebView;
import javafx.geometry.Insets;
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
    // Р’РєР»Р°РґРєР° 1: РђРЅР°Р»РёР· Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё РїСЂРѕРµРєС‚Р°
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

    // Р’С‹Р±РѕСЂ РјРѕРґРµР»Рё РґР»СЏ СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ (РїРѕРґРґРµСЂР¶РёРІР°РµС‚ РѕР±Р° РІРѕР·РјРѕР¶РЅС‹С… fx:id РёР· СЂР°Р·РјРµС‚РєРё)
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
    // Р’РєР»Р°РґРєР° 2: РЎРІРѕР±РѕРґРЅС‹Р№ С‡Р°С‚ СЃ РР
    // ==========================================
    @FXML private ComboBox<String> chatModelComboBox;
    @FXML private Button refreshModelsButton;
    @FXML private WebView generalChatWebView;
    @FXML private TextField generalChatPromptInput;
    @FXML private Button sendGeneralChatPromptButton;
    @FXML private Button clearGeneralChatButton;

    // ==========================================
    // Р’РєР»Р°РґРєР° 3: РР-РђРіРµРЅС‚ Р“РµРЅРµСЂР°С†РёРё РџСЂРѕРµРєС‚Р°
    // ==========================================
    @FXML private TextField agentWorkDirInput;
    @FXML private Button agentSelectFolderButton;
    @FXML private ComboBox<String> agentModelComboBox;
    @FXML private TextArea agentTaskPromptInput;
    @FXML private Button agentStartButton;
    @FXML private WebView agentLogWebView;

    // ==========================================
    // Р’РєР»Р°РґРєР° 4: РЎСЂР°РІРЅРёС‚РµР»СЊРЅС‹Р№ Р±РµРЅС‡РјР°СЂРєРёРЅРі
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
    // РЎРµСЂРІРёСЃС‹ Spring
    // ==========================================
    private final FileAnalyzer fileAnalyzer;
    private final CodeParser codeParser;
    private final OllamaClient ollamaClient;
    private final PdfReportService pdfReportService;
    private final FixRecommendationAgent fixRecommendationAgent;
    private final FixReviewService fixReviewService;
    private final AgentService agentService;
    private final SecurityScannerAgent securityScannerAgent;
    private final SemgrepReportService semgrepReportService;
    private final UnifiedScanService unifiedScanService;
    private final ScanExportService scanExportService;
    private String lastScanModel;
    private UnifiedScanService.ScanResult lastScanResult;

    // ==========================================
    // Р’РЅСѓС‚СЂРµРЅРЅРёРµ СЃРѕСЃС‚РѕСЏРЅРёСЏ Рё Р±СѓС„РµСЂС‹
    // ==========================================
    private final ObservableList<SourceFile> scannedFiles = FXCollections.observableArrayList();

    private final Parser markdownParser = Parser.builder().build();
    private final HtmlRenderer htmlRenderer = HtmlRenderer.builder().build();

    // HTML-Р±СѓС„РµСЂС‹ РґР»СЏ СЂРµРЅРґРµСЂРёРЅРіР° WebViews
    private final StringBuilder chatHistoryHtml = new StringBuilder();
    private final StringBuilder generalChatHtml = new StringBuilder();
    private final StringBuilder agentLogHtml = new StringBuilder();

    // Р•РґРёРЅР°СЏ РёСЃС‚РѕСЂРёСЏ СЃРѕРѕР±С‰РµРЅРёР№ РѕР±С‰РµРіРѕ С‡Р°С‚Р°
    private final List<ChatMessage> generalChatHistory = new ArrayList<>();

    public MainController(ProjectScanner projectScanner,
                          FileAnalyzer fileAnalyzer,
                          CodeParser codeParser,
                          OllamaClient ollamaClient,
                          PdfReportService pdfReportService,
                          FixRecommendationAgent fixRecommendationAgent,
                          FixReviewService fixReviewService,
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
        this.fixRecommendationAgent = fixRecommendationAgent;
        this.fixReviewService = fixReviewService;
        this.agentService = agentService;
        this.securityScannerAgent = securityScannerAgent;
        this.benchmarkService = benchmarkService;
        this.semgrepReportService = semgrepReportService;
        this.unifiedScanService = unifiedScanService;
        this.scanExportService = scanExportService;
    }

    @FXML
    public void initialize() {
        // 1. РќР°СЃС‚СЂРѕР№РєР° С‚Р°Р±Р»РёС†С‹ СѓСЏР·РІРёРјРѕСЃС‚РµР№
        if (titleColumn != null) titleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        if (severityColumn != null) severityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        if (linesColumn != null) linesColumn.setCellValueFactory(new PropertyValueFactory<>("lineRange"));
        if (validationColumn != null) validationColumn.setCellValueFactory(
                new PropertyValueFactory<>("validationStatusLabel"));

        // 2. РћС„РѕСЂРјР»РµРЅРёРµ РґРµСЂРµРІР° С„Р°Р№Р»РѕРІ СЃ С‡РµРєР±РѕРєСЃР°РјРё Рё СЃС‚Р°С‚СѓСЃР°РјРё
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
                            setText(item.getName() + " вљ пёЏ (" + vulnCount + ")");
                            setStyle("-fx-text-fill: #c0392b; -fx-font-weight: bold;");
                        } else {
                            setText(item.getName() + " вњ…");
                            setStyle("-fx-text-fill: #27ae60; -fx-font-weight: normal;");
                        }
                    } else {
                        setText(item.getName());
                        setStyle("-fx-text-fill: #2c3e50;");
                    }
                }
            });

            // 3. РЎР»СѓС€Р°С‚РµР»Рё РІС‹Р±РѕСЂР° С„Р°Р№Р»РѕРІ Рё СѓСЏР·РІРёРјРѕСЃС‚РµР№
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

        // 4. РќР°Р·РЅР°С‡РµРЅРёРµ РѕР±СЂР°Р±РѕС‚С‡РёРєРѕРІ СЃРѕР±С‹С‚РёР№ РґР»СЏ РїРµСЂРІРѕР№ РІРєР»Р°РґРєРё
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

        // 5. РќР°Р·РЅР°С‡РµРЅРёРµ РѕР±СЂР°Р±РѕС‚С‡РёРєРѕРІ СЃРѕР±С‹С‚РёР№ РґР»СЏ СЃРІРѕР±РѕРґРЅРѕРіРѕ С‡Р°С‚Р°
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

        // РќР°СЃС‚СЂРѕР№РєР° РєРѕР»РѕРЅРѕРє С‚Р°Р±Р»РёС†С‹ Р±РµРЅС‡РјР°СЂРєР°
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

        // РЎР±СЂРѕСЃ РѕРєРѕРЅ WebView Рё Р·Р°РіСЂСѓР·РєР° РјРѕРґРµР»РµР№
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
     * РџРѕР»СѓС‡РёС‚СЊ РІС‹Р±СЂР°РЅРЅСѓСЋ РјРѕРґРµР»СЊ РґР»СЏ РІРєР»Р°РґРєРё СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ
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
    // Р›РћР“РРљРђ Р’РљР›РђР”РљР РР-РђР“Р•РќРўРђ
    // ==========================================

    @FXML
    private void handleAgentSelectFolder() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Р’С‹Р±РµСЂРёС‚Рµ СЂР°Р±РѕС‡СѓСЋ РїР°РїРєСѓ РґР»СЏ СЃРѕР·РґР°РЅРёСЏ РїСЂРѕРµРєС‚Р°");

        Stage stage = (Stage) agentSelectFolderButton.getScene().getWindow();
        File folder = directoryChooser.showDialog(stage);

        if (folder != null) {
            agentWorkDirInput.setText(folder.getAbsolutePath());
        }
    }


    @FXML
    private void handleSelectBenchmarkFolder() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Р’С‹Р±РµСЂРёС‚Рµ РґРёСЂРµРєС‚РѕСЂРёСЋ СЃ Р±РµРЅС‡РјР°СЂРє-С„Р°Р№Р»Р°РјРё");
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
            new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° СѓРєР°Р¶РёС‚Рµ РїР°РїРєСѓ СЃ С‚РµСЃС‚РѕРІС‹РјРё С„Р°Р№Р»Р°РјРё!").showAndWait();
            return;
        }

        File[] files = benchmarkFolder.listFiles(f -> f.isFile() && !f.getName().startsWith("."));
        if (files == null || files.length == 0) {
            new Alert(Alert.AlertType.WARNING, "Р’ РІС‹Р±СЂР°РЅРЅРѕР№ РїР°РїРєРµ РЅРµС‚ РїРѕРґС…РѕРґСЏС‰РёС… С„Р°Р№Р»РѕРІ!").showAndWait();
            return;
        }

        List<String> models = ollamaClient.getAvailableModels();
        if (models.isEmpty()) {
            new Alert(Alert.AlertType.WARNING, "Р’ Ollama РЅРµ РЅР°Р№РґРµРЅРѕ Р°РєС‚РёРІРЅС‹С… РјРѕРґРµР»РµР№!").showAndWait();
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
            new Alert(Alert.AlertType.ERROR, "РћС€РёР±РєР° РІС‹РїРѕР»РЅРµРЅРёСЏ Р±РµРЅС‡РјР°СЂРєР°: " + task.getException().getMessage()).showAndWait();
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
            Alert alert = new Alert(Alert.AlertType.WARNING, "РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РІС‹Р±РµСЂРёС‚Рµ СЂР°Р±РѕС‡СѓСЋ РїР°РїРєСѓ!");
            alert.showAndWait();
            return;
        }

        if (prompt.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РѕРїРёС€РёС‚Рµ Р·Р°РґР°С‡Сѓ РґР»СЏ Р°РіРµРЅС‚Р°!");
            alert.showAndWait();
            return;
        }

        if (selectedModel == null || selectedModel.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РІС‹Р±РµСЂРёС‚Рµ РјРѕРґРµР»СЊ РґР»СЏ РіРµРЅРµСЂР°С†РёРё!");
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
            appendAgentLog("вќЊ **РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР° РїСЂРё СЂР°Р±РѕС‚Рµ Р°РіРµРЅС‚Р°:** " + agentTask.getException().getMessage());
        });

        Thread thread = new Thread(agentTask);
        thread.setDaemon(true);
        thread.start();
    }

    // ==========================================
    // Р›РћР“РРљРђ РЎР’РћР‘РћР”РќРћР“Рћ Р§РђРўРђ
    // ==========================================

    @FXML
    private void handleClearGeneralChat() {
        generalChatHistory.clear();
        resetGeneralChatHtml();
        appendGeneralChatMessage("РЎРёСЃС‚РµРјР°", "рџ§№ **Р§Р°С‚ Рё РєРѕРЅС‚РµРєСЃС‚ РґРёР°Р»РѕРіР° СѓСЃРїРµС€РЅРѕ СЃР±СЂРѕС€РµРЅС‹.**");
    }

    private void handleSendGeneralChatPrompt() {
        if (generalChatPromptInput == null) return;

        String prompt = generalChatPromptInput.getText().trim();
        String selectedModel = (chatModelComboBox != null) ? chatModelComboBox.getValue() : null;

        if (prompt.isEmpty()) return;

        if (selectedModel == null || selectedModel.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РІС‹Р±РµСЂРёС‚Рµ РјРѕРґРµР»СЊ РґР»СЏ РѕР±С‰РµРЅРёСЏ!");
            alert.showAndWait();
            return;
        }

        appendGeneralChatMessage("Р’С‹", prompt);
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
            appendGeneralChatMessage("РР (" + selectedModel + ")", response);
        });

        chatTask.setOnFailed(e -> {
            if (sendGeneralChatPromptButton != null) sendGeneralChatPromptButton.setDisable(false);
            appendGeneralChatMessage("РЎРёСЃС‚РµРјР°", "вќЊ **РћС€РёР±РєР° РІР·Р°РёРјРѕРґРµР№СЃС‚РІРёСЏ СЃ РјРѕРґРµР»СЊСЋ.**");
        });

        Thread thread = new Thread(chatTask);
        thread.setDaemon(true);
        thread.start();
    }

    // ==========================================
    // Р›РћР“РРљРђ РђРќРђР›РР—Рђ РљРћР”Рђ Р РЎРљРђРќР•Р Рђ
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
        directoryChooser.setTitle("Р’С‹Р±РµСЂРёС‚Рµ РїР°РїРєСѓ СЃ РёСЃС…РѕРґРЅС‹Рј РєРѕРґРѕРј");
        Stage stage = (Stage) selectFolderButton.getScene().getWindow();
        File folder = directoryChooser.showDialog(stage);

        if (folder != null && folder.exists()) {
            selectAllCheckBox.setSelected(true);
            lastScanResult = null;
            buildFileTree(folder);
            scanButton.setDisable(false);
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "рџ“Ѓ Р—Р°РіСЂСѓР¶РµРЅ РїСЂРѕРµРєС‚: `" + folder.getName() + "`.");
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
        appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "рџ§№ РџСЂРѕРµРєС‚ Рё СЂРµР·СѓР»СЊС‚Р°С‚С‹ Р°РЅР°Р»РёР·Р° РѕС‡РёС‰РµРЅС‹.");
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

                    // Р¤РёР»СЊС‚СЂСѓРµРј СЃР»СѓР¶РµР±РЅС‹Рµ РґРёСЂРµРєС‚РѕСЂРёРё Рё Р±РёРЅР°СЂРЅС‹Рµ РєР»Р°СЃСЃС‹
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
            new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° РІС‹Р±РµСЂРёС‚Рµ РїР°РїРєСѓ РїСЂРѕРµРєС‚Р°.").showAndWait();
            return;
        }

        List<File> selectedFiles = new ArrayList<>();
        collectSelectedFiles((CheckBoxTreeItem<File>) fileTreeView.getRoot(), selectedFiles);
        if (selectedFiles.isEmpty()) {
            new Alert(Alert.AlertType.WARNING, "Р’С‹ РЅРµ РІС‹Р±СЂР°Р»Рё РЅРё РѕРґРЅРѕРіРѕ С„Р°Р№Р»Р°!").showAndWait();
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
        scanButton.setText("LLM + Semgrep: РёРґС‘С‚ Р°РЅР°Р»РёР·...");
        appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "рџ”Ќ **Р—Р°РїСѓС‰РµРЅС‹ Semgrep Рё LLM.** РњРѕРґРµР»СЊ: `"
                + targetModel + "`. РСЃС…РѕРґРЅС‹Р№ РєРѕРґ РЅРµ Р·Р°РїСѓСЃРєР°РµС‚СЃСЏ; Semgrep СЂР°Р±РѕС‚Р°РµС‚ РІ РѕС‚РґРµР»СЊРЅРѕРј РїСЂРѕС†РµСЃСЃРµ.");

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
                    && result.diagnostics().isEmpty() ? "вњ… РџСЂРѕРІРµСЂРєР° Р·Р°РІРµСЂС€РµРЅР°" : "вљ пёЏ РџСЂРѕРІРµСЂРєР° Р·Р°РІРµСЂС€РµРЅР° СЃ РѕРіСЂР°РЅРёС‡РµРЅРёСЏРјРё";
            StringBuilder summary = new StringBuilder(status)
                    .append(". Р¤Р°Р№Р»РѕРІ Р·Р°РіСЂСѓР¶РµРЅРѕ: ").append(result.files().size())
                    .append(". LLM СѓСЃРїРµС€РЅРѕ РїСЂРѕРІРµСЂРёР»Р°: ").append(result.analyzedByLlm())
                    .append(", РЅРµРїРѕР»РЅС‹С… LLM: ").append(result.partialByLlm())
                    .append(", РѕС€РёР±РѕРє LLM: ").append(result.failedByLlm())
                    .append(". Semgrep: ").append(result.sastCompleted()
                            ? result.sastFindings() + " СЃСЂР°Р±Р°С‚С‹РІР°РЅРёР№" : "РЅРµ РІС‹РїРѕР»РЅРµРЅ")
                    .append(". РР-СЂРµРІСЊСЋ SAST: ").append(result.aiReviewed())
                    .append(" РѕС†РµРЅРµРЅРѕ, ").append(result.aiReviewFailed()).append(" РѕС€РёР±РѕРє, ")
                    .append(result.aiReviewSkipped()).append(" РїСЂРѕРїСѓС‰РµРЅРѕ")
                    .append(". Р’РѕР·РјРѕР¶РЅС‹С… СЃРѕРІРїР°РґРµРЅРёР№ СЃС‚СЂРѕРє: ").append(result.possibleOverlaps())
                    .append(". РџСЂРѕРїСѓС‰РµРЅРѕ С„Р°Р№Р»РѕРІ: ").append(result.skippedTargets())
                    .append(". РќРµСЃРѕРїРѕСЃС‚Р°РІР»РµРЅРЅС‹С… SAST-РЅР°С…РѕРґРѕРє: ").append(result.unrelatedFindings())
                    .append(".\n\n**Р’Р°Р¶РЅРѕ:** СЃРѕРІРїР°РґРµРЅРёРµ СЃС‚СЂРѕРє РЅРµ РїРѕРґС‚РІРµСЂР¶РґР°РµС‚ СѓСЏР·РІРёРјРѕСЃС‚СЊ; РѕС‚СЃСѓС‚СЃС‚РІРёРµ РЅР°С…РѕРґРѕРє РЅРµ РіР°СЂР°РЅС‚РёСЂСѓРµС‚ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚СЊ.");
            for (String diagnostic : result.diagnostics()) {
                summary.append("\n\nвљ пёЏ ").append(escapeHtml(diagnostic));
            }
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", summary.toString());
        });
        task.setOnFailed(e -> {
            finishUnifiedScan();
            Throwable error = task.getException();
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "вќЊ **РћС€РёР±РєР° Р°РЅР°Р»РёР·Р°:** "
                    + (error == null ? "РЅРµРёР·РІРµСЃС‚РЅР°СЏ РѕС€РёР±РєР°" : escapeHtml(error.getMessage()))
                    + "\n\nР РµР·СѓР»СЊС‚Р°С‚ РЅРµР»СЊР·СЏ РёРЅС‚РµСЂРїСЂРµС‚РёСЂРѕРІР°С‚СЊ РєР°Рє РѕС‚СЃСѓС‚СЃС‚РІРёРµ СѓСЏР·РІРёРјРѕСЃС‚РµР№.");
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
        scanButton.setText("рџљЂ Р—Р°РїСѓСЃС‚РёС‚СЊ Р°РЅР°Р»РёР· РІС‹Р±СЂР°РЅРЅС‹С…");
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
                "### вљ пёЏ %s\n\n**РљСЂРёС‚РёС‡РЅРѕСЃС‚СЊ:** `%s`  \n**РЎС‚СЂРѕРєРё:** `%s`  \n**РЎС‚Р°С‚СѓСЃ:** %s\n\n**РџРѕСЏСЃРЅРµРЅРёРµ:** %s\n\n**РР-СЂРµРІСЊСЋ:** %s\n\n**РћР±РѕСЃРЅРѕРІР°РЅРёРµ РР:** %s\n\n#### РћРїРёСЃР°РЅРёРµ:\n%s\n\n#### Р РµРєРѕРјРµРЅРґР°С†РёСЏ:\n%s",
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
            markdownReport += "\n\n**РћС†РµРЅРєР° CWE РїРѕ РєРѕРґСѓ:** `" + escapeHtml(vulnerability.getCweAdvisorStatus()) + "`";
            if (vulnerability.getCweSuggestion() != null) {
                markdownReport += "\n\n**РџСЂРµРґР»Р°РіР°РµРјР°СЏ РєР°С‚РµРіРѕСЂРёСЏ (РЅРµ РґРёР°РіРЅРѕР·):** `"
                        + escapeHtml(vulnerability.getCweSuggestion()) + "`";
            }
            if (vulnerability.getCweAdvisorNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getCweAdvisorNote());
            }
        }
        if (vulnerability.getSemanticStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getSemanticStatus())) {
            markdownReport += "\n\n**РџСЂРѕРІРµСЂРєР° CWE:** `" + escapeHtml(vulnerability.getSemanticStatus()) + "`";
            if (vulnerability.getSemanticNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getSemanticNote());
            }
        }
        if (vulnerability.getMechanismStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getMechanismStatus())) {
            markdownReport += "\n\n**РџСЂРѕРІРµСЂРєР° РјРµС…Р°РЅРёР·РјР°:** `" + escapeHtml(vulnerability.getMechanismStatus()) + "`";
            if (vulnerability.getMechanismNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getMechanismNote());
            }
        }
        if (vulnerability.getEvidence() != null) {
            markdownReport += "\n\n**Р¦РёС‚Р°С‚Р° РёСЃС…РѕРґРЅРѕРіРѕ РєРѕРґР° (LLM):** `"
                    + escapeHtml(vulnerability.getEvidence().replace("`", "'")) + "`";
        }
        if (vulnerability.getModelOutputStatus() != null
                && !"NOT_ASSESSED".equals(vulnerability.getModelOutputStatus())) {
            markdownReport += "\n\n**РљР°С‡РµСЃС‚РІРѕ РѕС‚РІРµС‚Р° LLM:** `"
                    + escapeHtml(vulnerability.getModelOutputStatus()) + "`";
            if (vulnerability.getModelOutputNote() != null) {
                markdownReport += "\n\n" + escapeHtml(vulnerability.getModelOutputNote());
            }
        }
        if (vulnerability.getSourceExcerpt() != null) {
            markdownReport += "\n\n**РСЃС…РѕРґРЅР°СЏ СЃС‚СЂРѕРєР° (РґР»СЏ СЂСѓС‡РЅРѕР№ СЃРІРµСЂРєРё, РЅРµ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ):** `"
                    + escapeHtml(vulnerability.getSourceExcerpt().replace("`", "'")) + "`";
        }
        appendMessageToChatHtml("РР-РђРЅР°Р»РёР·Р°С‚РѕСЂ", markdownReport);
    }

    /**
     * Imports a previously generated Semgrep JSON report for the selected project.
     * Import is deliberately read-only: it never invokes external code or applies fixes.
     */
    private void handleImportSemgrepClick() {
        if (fileTreeView == null || fileTreeView.getRoot() == null) {
            new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° РІС‹Р±РµСЂРёС‚Рµ РїР°РїРєСѓ РїСЂРѕРµРєС‚Р°.").showAndWait();
            return;
        }
        File projectFolder = fileTreeView.getRoot().getValue();
        if (projectFolder == null || !projectFolder.isDirectory()) {
            new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° РІС‹Р±РµСЂРёС‚Рµ РїР°РїРєСѓ РїСЂРѕРµРєС‚Р°.").showAndWait();
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("РћС‚РєСЂС‹С‚СЊ JSON-РѕС‚С‡С‘С‚ Semgrep");
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
            new Alert(Alert.AlertType.ERROR, "РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РёС‚Р°С‚СЊ Semgrep JSON: " + ex.getMessage()).showAndWait();
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
                    v.setValidationNote("РРјРїРѕСЂС‚РёСЂРѕРІР°РЅ РЅРѕРІС‹Р№ РѕС‚С‡С‘С‚ Semgrep; СЃС‚Р°СЂРѕРµ СЃРѕРІРїР°РґРµРЅРёРµ СЃР±СЂРѕС€РµРЅРѕ. "
                            + "РџСЂРѕРІРµСЂРєР° РєРѕРѕСЂРґРёРЅР°С‚ LLM РЅРµ РїРѕРґС‚РІРµСЂР¶РґР°РµС‚ СѓСЏР·РІРёРјРѕСЃС‚СЊ.");
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
        String summary = "Semgrep: РІ РѕС‚С‡С‘С‚Рµ " + report.findings().size() + " СЃСЂР°Р±Р°С‚С‹РІР°РЅРёР№, "
                + "РёРјРїРѕСЂС‚РёСЂРѕРІР°РЅРѕ " + imported + ", РЅРµ СЃРѕРїРѕСЃС‚Р°РІР»РµРЅРѕ СЃ РїСЂРѕРµРєС‚РѕРј " + missing
                + ", РґРёР°РіРЅРѕСЃС‚РёС‡РµСЃРєРёС… РѕС€РёР±РѕРє " + report.errors().size() + ".";
        appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", summary + "\n\n**Р’РЅРёРјР°РЅРёРµ:** РЎРµРјРіСЂРµРї-РЅР°С…РѕРґРєРё РЅРµ РїРѕРґС‚РІРµСЂР¶РґР°СЋС‚ "
                + "СЌРєСЃРїР»СѓР°С‚РёСЂСѓРµРјРѕСЃС‚СЊ; РЅРѕР»СЊ РЅР°С…РѕРґРѕРє РЅРµ РіР°СЂР°РЅС‚РёСЂСѓРµС‚ РѕС‚СЃСѓС‚СЃС‚РІРёРµ СѓСЏР·РІРёРјРѕСЃС‚РµР№.");
        if (missing > 0 || report.hasErrors()) {
            new Alert(Alert.AlertType.WARNING, summary + "\nРџСЂРѕРІРµСЂСЊС‚Рµ РїРѕР»РЅРѕС‚Сѓ РѕС‚С‡С‘С‚Р° Рё РїСѓС‚Рё Рє С„Р°Р№Р»Р°Рј.").showAndWait();
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
            new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° РїСЂРѕСЃРєР°РЅРёСЂСѓР№С‚Рµ РїСЂРѕРµРєС‚ РёР»Рё РёРјРїРѕСЂС‚РёСЂСѓР№С‚Рµ РѕС‚С‡С‘С‚.").showAndWait();
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Р­РєСЃРїРѕСЂС‚ РЅРµРѕР±СЂР°Р±РѕС‚Р°РЅРЅС‹С… СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ (РІРѕР·РјРѕР¶РЅС‹ С„СЂР°РіРјРµРЅС‚С‹ СЃРµРєСЂРµС‚РѕРІ)");
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
            new Alert(Alert.AlertType.INFORMATION, "Р­РєСЃРїРѕСЂС‚ СЃРѕС…СЂР°РЅС‘РЅ. РќРµ РїСѓР±Р»РёРєСѓР№С‚Рµ С„Р°Р№Р» Р±РµР· РїСЂРѕРІРµСЂРєРё СЃРµРєСЂРµС‚РѕРІ.")
                    .showAndWait();
        } catch (IOException ex) {
            new Alert(Alert.AlertType.ERROR, "РћС€РёР±РєР° СЌРєСЃРїРѕСЂС‚Р°: " + ex.getMessage()).showAndWait();
        }
    }

    private void handleExportPdfClick() {
        if (scannedFiles.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "РЎРЅР°С‡Р°Р»Р° РЅРµРѕР±С…РѕРґРёРјРѕ РїСЂРѕСЃРєР°РЅРёСЂРѕРІР°С‚СЊ РїСЂРѕРµРєС‚!");
            alert.showAndWait();
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("РЎРѕС…СЂР°РЅРёС‚СЊ PDF РѕС‚С‡РµС‚");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PDF Documents (*.pdf)", "*.pdf"));
        fileChooser.setInitialFileName("security_report.pdf");

        Stage stage = (Stage) exportPdfButton.getScene().getWindow();
        File saveFile = fileChooser.showSaveDialog(stage);

        if (saveFile != null) {
            try {
                String coverage = lastScanResult == null ?
                        "РЎРѕСЃС‚РѕСЏРЅРёРµ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРѕР№ РїСЂРѕРІРµСЂРєРё РЅРµРёР·РІРµСЃС‚РЅРѕ (РІРѕР·РјРѕР¶РµРЅ СЂСѓС‡РЅРѕР№ РёРјРїРѕСЂС‚)." :
                        "LLM: " + lastScanResult.analyzedByLlm() + " С„Р°Р№Р»РѕРІ СѓСЃРїРµС€РЅРѕ, "
                        + lastScanResult.failedByLlm() + " РѕС€РёР±РѕРє, "
                        + lastScanResult.partialByLlm() + " РЅРµРїРѕР»РЅС‹С…; Semgrep: "
                        + (lastScanResult.sastCompleted() ? "Р·Р°РїСѓС‰РµРЅ" : "РЅРµ РІС‹РїРѕР»РЅРµРЅ")
                        + "; РїСЂРѕРїСѓС‰РµРЅРѕ С„Р°Р№Р»РѕРІ: " + lastScanResult.skippedTargets()
                        + "; РґРёР°РіРЅРѕСЃС‚РёРє: " + lastScanResult.diagnostics().size() + ".";
                pdfReportService.generatePdfReport(scannedFiles, saveFile.getAbsolutePath(), coverage);
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "PDF-РѕС‚С‡РµС‚ СѓСЃРїРµС€РЅРѕ СЃРѕС…СЂР°РЅРµРЅ!");
                alert.showAndWait();
            } catch (Exception e) {
                Alert alert = new Alert(Alert.AlertType.ERROR, "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ PDF-РѕС‚С‡РµС‚: " + e.getMessage());
                alert.showAndWait();
            }
        }
    }

    private void handlePasteAndAnalyzeCode() {
        Dialog<String> dialog = new Dialog<>();
        dialog.setTitle("Р‘С‹СЃС‚СЂС‹Р№ Р°РЅР°Р»РёР· РєРѕРґР°");
        dialog.setHeaderText("Р’СЃС‚Р°РІСЊС‚Рµ С„СЂР°РіРјРµРЅС‚ РєРѕРґР° РґР»СЏ Р°РЅР°Р»РёР·Р° (Ctrl+V)");

        ButtonType analyzeButtonType = new ButtonType("РђРЅР°Р»РёР·РёСЂРѕРІР°С‚СЊ", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(analyzeButtonType, ButtonType.CANCEL);

        TextArea textArea = new TextArea();
        textArea.setPromptText("Р’СЃС‚Р°РІСЊС‚Рµ С„СЂР°РіРјРµРЅС‚ РєРѕРґР° (C, C++, Java, Python, Go)...");
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
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "вЏі *Р’С‹РїРѕР»РЅСЏРµС‚СЃСЏ СЌРєСЃРїСЂРµСЃСЃ-Р°РЅР°Р»РёР· РјРѕРґРµР»СЊСЋ `" + targetModel + "`...*");

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
                    appendMessageToChatHtml("РР-РљРѕРЅСЃСѓР»СЊС‚Р°РЅС‚ (" + targetModel + ")", "вњ… **РЈСЏР·РІРёРјРѕСЃС‚Рё РІРѕ С„СЂР°РіРјРµРЅС‚Рµ РєРѕРґР° РЅРµ РѕР±РЅР°СЂСѓР¶РµРЅС‹!**");
                } else {
                    appendMessageToChatHtml("РР-РљРѕРЅСЃСѓР»СЊС‚Р°РЅС‚ (" + targetModel + ")", "вљ пёЏ **РђРЅР°Р»РёР· Р·Р°РІРµСЂС€РµРЅ!** РћР±РЅР°СЂСѓР¶РµРЅРѕ СѓСЏР·РІРёРјРѕСЃС‚РµР№: **" + vulnerabilities.size() + "**.");
                }
            });

            analyzeTask.setOnFailed(e -> {
                pasteCodeButton.setDisable(false);
                appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "вќЊ **РћС€РёР±РєР° РІРѕ РІСЂРµРјСЏ Р°РЅР°Р»РёР·Р° С„СЂР°РіРјРµРЅС‚Р° РєРѕРґР°:** " + analyzeTask.getException().getMessage());
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
            Alert alert = new Alert(Alert.AlertType.WARNING, "РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РІС‹Р±РµСЂРёС‚Рµ С„Р°Р№Р» РІ РґРµСЂРµРІРµ Рё РєРѕРЅРєСЂРµС‚РЅСѓСЋ СѓСЏР·РІРёРјРѕСЃС‚СЊ РІ С‚Р°Р±Р»РёС†Рµ!");
            alert.showAndWait();
            return;
        }

        SourceFile selectedSourceFile = scannedFiles.stream()
                .filter(sf -> sf.getAbsolutePath() != null && sf.getAbsolutePath().equals(selectedTreeItem.getValue().getAbsolutePath()))
                .findFirst()
                .orElse(null);

        if (selectedSourceFile == null) return;

        String targetModel = getSelectedScanModel();
        appendMessageToChatHtml("Р’С‹", question);
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
            appendMessageToChatHtml("РР-РљРѕРЅСЃСѓР»СЊС‚Р°РЅС‚ (" + targetModel + ")", chatTask.getValue());
        });

        chatTask.setOnFailed(e -> {
            sendPromptButton.setDisable(false);
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "**РћС€РёР±РєР° РїРѕР»СѓС‡РµРЅРёСЏ РѕС‚РІРµС‚Р° РѕС‚ РР.**");
        });

        Thread thread = new Thread(chatTask);
        thread.setDaemon(true);
        thread.start();
    }

    // 8.7: A generated correction is NEVER directly written to original source code.
    private void handleFixCurrentFileClick() {
        TreeItem<File> selected = fileTreeView.getSelectionModel().getSelectedItem();
        if (selected == null || selected.getValue() == null) {
            new Alert(Alert.AlertType.WARNING, "Р’С‹Р±РµСЂРёС‚Рµ С„Р°Р№Р» СЃ СЂРµР·СѓР»СЊС‚Р°С‚Р°РјРё Р°РЅР°Р»РёР·Р°.").showAndWait();
            return;
        }
        SourceFile source = scannedFiles.stream()
                .filter(sf -> sf.getAbsolutePath() != null
                        && sf.getAbsolutePath().equals(selected.getValue().getAbsolutePath()))
                .findFirst().orElse(null);
        if (source == null || source.getVulnerabilities().isEmpty()) {
            new Alert(Alert.AlertType.INFORMATION, "Р”Р»СЏ СЌС‚РѕРіРѕ С„Р°Р№Р»Р° РЅРµС‚ РЅР°С…РѕРґРѕРє.").showAndWait();
            return;
        }
        fixCurrentFileButton.setDisable(true);
        String model = getSelectedScanModel();
        appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "Р“РµРЅРµСЂРёСЂСѓРµС‚СЃСЏ **РїСЂРµРґР»РѕР¶РµРЅРёРµ** РёСЃРїСЂР°РІР»РµРЅРёСЏ `"
                + escapeHtml(source.getName()) + "` (РјРѕРґРµР»СЊ `" + escapeHtml(model) + "`). "
                + "РСЃС…РѕРґРЅС‹Р№ С„Р°Р№Р» РЅРµ РјРµРЅСЏРµС‚СЃСЏ.");
        Task<FixProposal> task = new Task<>() {
            @Override protected FixProposal call() throws Exception {
                return fixRecommendationAgent.propose(source, model);
            }
        };
        task.setOnSucceeded(event -> {
            fixCurrentFileButton.setDisable(false);
            showFixProposalDialog(task.getValue());
        });
        task.setOnFailed(event -> {
            fixCurrentFileButton.setDisable(false);
            Throwable failure = task.getException();
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕРґРіРѕС‚РѕРІРёС‚СЊ РїСЂРµРґР»РѕР¶РµРЅРёРµ: "
                    + escapeHtml(failure == null ? "РЅРµРёР·РІРµСЃС‚РЅР°СЏ РѕС€РёР±РєР°" : failure.getMessage()));
        });
        Thread thread = new Thread(task, "fix-proposal");
        thread.setDaemon(true);
        thread.start();
    }

    private void handleFixAllClick() {
        List<SourceFile> candidates = scannedFiles.stream()
                .filter(sf -> sf.getPath() != null && !sf.getVulnerabilities().isEmpty())
                .limit(5).toList();
        if (candidates.isEmpty()) {
            new Alert(Alert.AlertType.INFORMATION, "РЎРЅР°С‡Р°Р»Р° РїСЂРѕР°РЅР°Р»РёР·РёСЂСѓР№С‚Рµ С„Р°Р№Р»С‹ РїСЂРѕРµРєС‚Р°.").showAndWait();
            return;
        }
        Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION,
                "РЎС„РѕСЂРјРёСЂРѕРІР°С‚СЊ РїСЂРµРґР»РѕР¶РµРЅРёСЏ РјР°РєСЃРёРјСѓРј РґР»СЏ " + candidates.size()
                        + " С„Р°Р№Р»РѕРІ? Р’СЃРµ РїСЂРµРґР»РѕР¶РµРЅРёСЏ Р±СѓРґСѓС‚ РїРѕРєР°Р·Р°РЅС‹ РїРѕ РѕС‡РµСЂРµРґРё; "
                        + "РѕСЂРёРіРёРЅР°Р»С‹ РЅРµ РёР·РјРµРЅСЏС‚СЃСЏ Рё РЅРёС‡РµРіРѕ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РЅРµ СЃРѕС…СЂР°РЅРёС‚СЃСЏ.",
                ButtonType.YES, ButtonType.CANCEL);
        if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.YES) return;
        String model = getSelectedScanModel();
        fixAllButton.setDisable(true);
        Task<List<FixProposal>> task = new Task<>() {
            @Override protected List<FixProposal> call() {
                List<FixProposal> suggestions = new ArrayList<>();
                for (SourceFile sf : candidates) {
                    try {
                        suggestions.add(fixRecommendationAgent.propose(sf, model));
                    } catch (Exception ex) {
                        String filename = sf.getName();
                        String message = ex.getMessage();
                        Platform.runLater(() -> appendMessageToChatHtml("РЎРёСЃС‚РµРјР°",
                                "РџСЂРѕРїСѓС‰РµРЅРѕ `" + escapeHtml(filename) + "`: " + escapeHtml(message)));
                    }
                }
                return suggestions;
            }
        };
        task.setOnSucceeded(event -> {
            fixAllButton.setDisable(false);
            List<FixProposal> results = task.getValue();
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "РЎРѕР·РґР°РЅРѕ РїСЂРµРґР»РѕР¶РµРЅРёР№: " + results.size()
                    + ". РљР°Р¶РґРѕРµ С‚СЂРµР±СѓРµС‚ РѕС‚РґРµР»СЊРЅРѕРіРѕ РїСЂРѕСЃРјРѕС‚СЂР° Рё СЂРµС€РµРЅРёСЏ Рѕ СЃРѕС…СЂР°РЅРµРЅРёРё.");
            for (FixProposal proposal : results) showFixProposalDialog(proposal);
        });
        task.setOnFailed(event -> {
            fixAllButton.setDisable(false);
            appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "РџР°РєРµС‚РЅР°СЏ РіРµРЅРµСЂР°С†РёСЏ РЅРµ Р·Р°РІРµСЂС€РёР»Р°СЃСЊ: "
                    + escapeHtml(task.getException().getMessage()));
        });
        Thread thread = new Thread(task, "fix-proposal-batch");
        thread.setDaemon(true);
        thread.start();
    }

    private void showFixProposalDialog(FixProposal proposal) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Fix Recommendation Agent вЂ” СЂСѓС‡РЅРѕР№ РїСЂРѕСЃРјРѕС‚СЂ");
        dialog.setHeaderText("РџСЂРµРґР»РѕР¶РµРЅРёРµ РґР»СЏ: " + proposal.sourcePath().getFileName());
        ButtonType saveType = new ButtonType("РЎРѕС…СЂР°РЅРёС‚СЊ РѕС‚РґРµР»СЊРЅРѕ...", ButtonBar.ButtonData.APPLY);
        ButtonType checkType = new ButtonType("РџРѕРІС‚РѕСЂРЅРѕ РїСЂРѕРІРµСЂРёС‚СЊ Semgrep", ButtonBar.ButtonData.OTHER);
        dialog.getDialogPane().getButtonTypes().addAll(checkType, saveType, ButtonType.CLOSE);

        TextArea before = fixPreviewArea(proposal.originalContent());
        TextArea after = fixPreviewArea(proposal.proposedContent());
        TextArea diff = fixPreviewArea(proposal.diffPreview());
        TabPane tabs = new TabPane(
                new Tab("РР·РјРµРЅРµРЅРёСЏ (-/+)", diff),
                new Tab("РСЃС…РѕРґРЅРёРє", before),
                new Tab("РџСЂРµРґР»РѕР¶РµРЅРёРµ LLM", after));
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        Label info = new Label(proposal.reviewNotes()
                + "\nРЎРѕС…СЂР°РЅСЏР№С‚Рµ С‚РѕР»СЊРєРѕ РІ РЅРѕРІС‹Р№ С„Р°Р№Р»; РєРѕРґ LLM РЅРµ РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё.");
        info.setWrapText(true);
        Label recheckStatus = new Label("Semgrep РґР»СЏ РїСЂРµРґР»РѕР¶РµРЅРЅРѕРіРѕ РєРѕРґР° РµС‰С‘ РЅРµ Р·Р°РїСѓСЃРєР°Р»СЃСЏ.");
        recheckStatus.setWrapText(true);
        VBox layout = new VBox(8, info, tabs, recheckStatus);
        layout.setPadding(new Insets(8));
        VBox.setVgrow(tabs, javafx.scene.layout.Priority.ALWAYS);
        dialog.getDialogPane().setContent(layout);
        dialog.getDialogPane().setPrefSize(950, 650);

        Button save = (Button) dialog.getDialogPane().lookupButton(saveType);
        save.addEventFilter(ActionEvent.ACTION, event -> {
            event.consume();
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Р­РєСЃРїРѕСЂС‚РёСЂРѕРІР°С‚СЊ РїСЂРµРґР»РѕР¶РµРЅРЅС‹Р№ РєРѕРґ РІ РЅРѕРІС‹Р№ С„Р°Р№Р»");
            String name = proposal.sourcePath().getFileName().toString();
            int dot = name.lastIndexOf('.');
            chooser.setInitialFileName(dot > 0
                    ? name.substring(0, dot) + ".proposed" + name.substring(dot)
                    : name + ".proposed.txt");
            File selected = chooser.showSaveDialog(dialog.getOwner());
            if (selected == null) return;
            try {
                Path output = fixReviewService.exportSeparate(proposal, selected.toPath());
                recheckStatus.setText("РџСЂРµРґР»РѕР¶РµРЅРёРµ СЃРѕС…СЂР°РЅРµРЅРѕ РѕС‚РґРµР»СЊРЅРѕ: " + output.getFileName());
                appendMessageToChatHtml("РЎРёСЃС‚РµРјР°", "РџСЂРµРґР»РѕР¶РµРЅРёРµ СЃРѕС…СЂР°РЅРµРЅРѕ РѕС‚РґРµР»СЊРЅРѕ: `"
                        + escapeHtml(output.toString()) + "`. РћСЂРёРіРёРЅР°Р» РЅРµ РёР·РјРµРЅС‘РЅ. "
                        + "РџРѕСЃР»Рµ СЂСѓС‡РЅРѕРіРѕ РїСЂРёРјРµРЅРµРЅРёСЏ РІС‹РїРѕР»РЅРёС‚Рµ РїРѕР»РЅС‹Р№ С‚РµСЃС‚РѕРІС‹Р№ РїСЂРѕРіРѕРЅ.");
            } catch (IOException ex) {
                new Alert(Alert.AlertType.WARNING, "РЎРѕС…СЂР°РЅРµРЅРёРµ РѕС‚РєР»РѕРЅРµРЅРѕ: " + ex.getMessage()).showAndWait();
            }
        });
        Button check = (Button) dialog.getDialogPane().lookupButton(checkType);
        check.addEventFilter(ActionEvent.ACTION, event -> {
            event.consume();
            TreeItem<File> tree = fileTreeView.getRoot();
            if (tree == null || tree.getValue() == null) {
                recheckStatus.setText("Р”Р»СЏ РїРѕРІС‚РѕСЂРЅРѕР№ РїСЂРѕРІРµСЂРєРё СЃРЅР°С‡Р°Р»Р° РІС‹Р±РµСЂРёС‚Рµ РїР°РїРєСѓ РїСЂРѕРµРєС‚Р°.");
                return;
            }
            Path root = tree.getValue().toPath();
            check.setDisable(true);
            recheckStatus.setText("Semgrep СЃСЂР°РІРЅРёРІР°РµС‚ РѕСЂРёРіРёРЅР°Р» Рё РїСЂРµРґР»РѕР¶РµРЅРЅС‹Р№ РєРѕРґ...");
            Task<FixReviewService.Recheck> task = new Task<>() {
                @Override protected FixReviewService.Recheck call() throws Exception {
                    return fixReviewService.recheckWithSemgrep(proposal, root);
                }
            };
            task.setOnSucceeded(done -> {
                check.setDisable(false);
                var result = task.getValue();
                recheckStatus.setText("Semgrep: РёСЃС…РѕРґРЅРёРє вЂ” " + result.baselineFindings()
                        + ", РїСЂРµРґР»РѕР¶РµРЅРёРµ вЂ” " + result.candidateFindings()
                        + ". РћС†РµРЅРёС‚Рµ РїСЂР°РІРёР»Р° РІСЂСѓС‡РЅСѓСЋ: " + result.candidateRules()
                        + ". РќРѕР»СЊ РЅР°С…РѕРґРѕРє РќР• РґРѕРєР°Р·С‹РІР°РµС‚ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚СЊ.");
            });
            task.setOnFailed(done -> {
                check.setDisable(false);
                recheckStatus.setText("РџРѕРІС‚РѕСЂРЅР°СЏ РїСЂРѕРІРµСЂРєР° РЅРµ Р·Р°РІРµСЂС€РµРЅР°: "
                        + task.getException().getMessage()
                        + ". Р РµР·СѓР»СЊС‚Р°С‚ РЅРµР»СЊР·СЏ СЃС‡РёС‚Р°С‚СЊ С‡РёСЃС‚С‹Рј.");
            });
            Thread thread = new Thread(task, "fix-proposal-semgrep-recheck");
            thread.setDaemon(true);
            thread.start();
        });
        dialog.showAndWait();
    }

    private static TextArea fixPreviewArea(String content) {
        TextArea area = new TextArea(content);
        area.setEditable(false);
        area.setWrapText(false);
        area.setStyle("-fx-font-family: Consolas, monospace; -fx-font-size: 12px;");
        return area;
    }

    // ==========================================
    // Р’РЎРџРћРњРћР“РђРўР•Р›Р¬РќР«Р• РњР•РўРћР”Р« HTML Р WEBVIEW
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
        String cssClass = sender.equals("Р’С‹") ? "user" : (sender.equals("РЎРёСЃС‚РµРјР°") ? "system" : "ai");
        String htmlContent = htmlRenderer.render(markdownParser.parse(markdownText));
        chatHistoryHtml.append("<div class='msg ").append(cssClass).append("'>")
                .append("<strong>").append(sender).append(":</strong><br/>")
                .append(htmlContent)
                .append("</div>");
        updateWebView(chatWebView, chatHistoryHtml);
    }

    private void appendGeneralChatMessage(String sender, String markdownText) {
        String cssClass = sender.equals("Р’С‹") ? "user" : (sender.equals("РЎРёСЃС‚РµРјР°") ? "system" : "ai");
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
