package com.analyzer.ui.theme;

import com.analyzer.domain.model.Vulnerability;
import javafx.application.Platform;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.web.WebView;
import javafx.stage.Stage;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;

/**
 * UI-only dashboard layer installed AFTER UiAppearanceManager.
 * It observes existing controls rather than changing scan or AI service logic.
 * Counters describe the visible tree/table, NOT completed scans or safety.
 */
public final class UiDashboardEnhancer {
    private static final String WEB_LIGHT = "/styles/web-light.css";
    private static final String WEB_DARK = "/styles/web-dark.css";

    private final VBox root;
    private final Scene scene;
    private final List<WebView> webViews = new ArrayList<>();
    private final String webLightCss = readResource(WEB_LIGHT);
    private final String webDarkCss = readResource(WEB_DARK);
    private final TableView<?> findingsTable;
    private final TreeView<?> fileTree;
    private final ComboBox<?> modelSelector;
    private final Label filesValue = new Label("0");
    private final Label findingsValue = new Label("0");
    private final Label highValue = new Label("0");
    private final Label modelStatus = new Label("Модель: не выбрана");
    private final Label tableStatus = new Label("Текущая таблица: 0 находок");
    private ObservableList<?> observedRows;
    private final ListChangeListener<Object> tableRowsListener = change -> refreshTableCounters();

    private UiDashboardEnhancer(VBox root, Scene scene) {
        this.root = root;
        this.scene = scene;
        this.findingsTable = findById(root, "vulnerabilitiesTable", TableView.class);
        this.fileTree = findById(root, "fileTreeView", TreeView.class);
        this.modelSelector = findById(root, "scanModelComboBox", ComboBox.class);
    }

    public static void install(Stage stage, Parent parent) {
        if (!(parent instanceof VBox root) || stage.getScene() == null) {
            throw new IllegalArgumentException("Интерфейс должен быть VBox с установленной Scene");
        }
        new UiDashboardEnhancer(root, stage.getScene()).install();
    }

    private void install() {
        addDashboard();
        addFooter();
        styleFindingsTable();
        updatePlaceholders();
        connectCounters();
        connectWebViews();
        scene.getStylesheets().addListener((ListChangeListener<String>) change -> {
            // The old theme manager swaps light/dark CSS; sync HTML on the FX thread.
            Platform.runLater(this::refreshWebViews);
        });
        refreshWebViews();
    }

    private void addDashboard() {
        TabPane tabs = null;
        for (Node child : root.getChildren()) {
            if (child instanceof TabPane pane) { tabs = pane; break; }
        }
        if (tabs == null || tabs.getTabs().isEmpty()
                || !(tabs.getTabs().getFirst().getContent() instanceof VBox scanPane)) return;

        FlowPane dashboard = new FlowPane();
        dashboard.getStyleClass().add("csa-dashboard");
        dashboard.setHgap(10);
        dashboard.setVgap(10);
        dashboard.setMaxWidth(Double.MAX_VALUE);
        dashboard.setAlignment(Pos.CENTER_LEFT);
        dashboard.setPadding(new Insets(2, 0, 2, 0));

        VBox filesCard = metricCard("ФАЙЛОВ В ДЕРЕВЕ", filesValue, "Не означает, что они проверены");
        VBox findingsCard = metricCard("НАХОДОК В ТАБЛИЦЕ", findingsValue, "Для выбранного файла");
        VBox highCard = metricCard("ВЫСОКИЙ РИСК", highValue, "HIGH в текущей таблице");
        dashboard.getChildren().addAll(filesCard, findingsCard, highCard);
        for (Node child : dashboard.getChildren()) {
            if (!(child instanceof Region card)) continue;
            card.prefWidthProperty().bind(javafx.beans.binding.Bindings.createDoubleBinding(() -> {
                double width = Math.max(1, dashboard.getWidth());
                int columns = width < 550 ? 1 : width < 850 ? 2 : 3;
                return Math.max(145, (width - (columns - 1) * dashboard.getHgap() - 3) / columns);
            }, dashboard.widthProperty()));
        }

        int insertIndex = 0;
        for (int i = 0; i < scanPane.getChildren().size(); i++) {
            if (scanPane.getChildren().get(i) instanceof SplitPane) {
                insertIndex = i;
                break;
            }
        }
        scanPane.getChildren().add(insertIndex, dashboard);
    }

    private static VBox metricCard(String title, Label value, String note) {
        VBox card = new VBox(3);
        card.getStyleClass().add("csa-metric-card");
        card.setMinWidth(145);
        Label heading = new Label(title);
        heading.getStyleClass().add("csa-metric-heading");
        value.getStyleClass().add("csa-metric-value");
        Label description = new Label(note);
        description.getStyleClass().add("csa-metric-note");
        description.setWrapText(true);
        card.getChildren().addAll(heading, value, description);
        return card;
    }

    private void addFooter() {
        FlowPane footer = new FlowPane();
        footer.getStyleClass().add("csa-footer");
        footer.setAlignment(Pos.CENTER_LEFT);
        footer.setHgap(20);
        footer.setVgap(5);
        footer.setPadding(new Insets(7, 10, 7, 10));
        modelStatus.getStyleClass().add("csa-footer-item");
        tableStatus.getStyleClass().add("csa-footer-item");
        Label caution = new Label("Semgrep: смотрите результаты проверки");
        caution.getStyleClass().add("csa-footer-muted");
        footer.getChildren().addAll(modelStatus, tableStatus, caution);
        root.getChildren().add(footer);
    }

    private void updatePlaceholders() {
        if (findingsTable != null) {
            findingsTable.setPlaceholder(placeholder("Находки пока не отображаются",
                    "Выберите Java-файл и выполните анализ. Пустая таблица не доказывает безопасность."));
        }
        visit(root, node -> {
            if (node instanceof TableView<?> table && table != findingsTable) {
                table.setPlaceholder(placeholder("Результатов пока нет",
                        "Запустите проверку на выбранном наборе данных."));
            }
        });
    }

    private static VBox placeholder(String title, String subtitle) {
        VBox box = new VBox(8);
        box.setAlignment(Pos.CENTER);
        box.getStyleClass().add("csa-placeholder");
        Label icon = new Label("⌕");
        icon.getStyleClass().add("csa-placeholder-icon");
        Label heading = new Label(title);
        heading.getStyleClass().add("csa-placeholder-title");
        Label description = new Label(subtitle);
        description.getStyleClass().add("csa-placeholder-description");
        description.setWrapText(true);
        description.setMaxWidth(470);
        box.getChildren().addAll(icon, heading, description);
        return box;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void styleFindingsTable() {
        if (findingsTable == null) return;
        for (TableColumn<?, ?> candidate : findingsTable.getColumns()) {
            if (!"severityColumn".equals(candidate.getId())) continue;
            TableColumn column = candidate;
            column.setCellFactory(col -> new TableCell<Object, Object>() {
                @Override
                protected void updateItem(Object item, boolean empty) {
                    super.updateItem(item, empty);
                    setText(null);
                    if (empty || item == null) { setGraphic(null); return; }
                    String severity = item.toString().strip().toUpperCase(Locale.ROOT);
                    Label pill = new Label(severity);
                    pill.getStyleClass().add("csa-risk-pill");
                    String style = switch (severity) {
                        case "HIGH", "CRITICAL", "ERROR" -> "csa-risk-high";
                        case "MEDIUM", "WARNING" -> "csa-risk-medium";
                        case "LOW" -> "csa-risk-low";
                        default -> "csa-risk-neutral";
                    };
                    pill.getStyleClass().add(style);
                    setGraphic(pill);
                }
            });
            break;
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void connectCounters() {
        if (fileTree != null) {
            fileTree.rootProperty().addListener((obs, oldValue, newValue) -> refreshFileCounter());
            refreshFileCounter();
        }
        if (findingsTable != null) {
            findingsTable.itemsProperty().addListener((obs, oldValue, newValue) -> {
                if (oldValue != null) ((ObservableList) oldValue).removeListener(tableRowsListener);
                if (newValue != null) ((ObservableList) newValue).addListener(tableRowsListener);
                refreshTableCounters();
            });
            if (findingsTable.getItems() != null) {
                ((ObservableList) findingsTable.getItems()).addListener(tableRowsListener);
            }
            refreshTableCounters();
        }
        if (modelSelector != null) {
            modelSelector.valueProperty().addListener((obs, oldValue, newValue) -> refreshModelLabel());
        }
        refreshModelLabel();
    }

    private void refreshFileCounter() {
        if (fileTree == null || fileTree.getRoot() == null) { filesValue.setText("0"); return; }
        int files = 0;
        ArrayDeque<TreeItem<?>> queue = new ArrayDeque<>();
        queue.add(fileTree.getRoot());
        while (!queue.isEmpty()) {
            TreeItem<?> item = queue.removeFirst();
            if (item.getValue() instanceof java.io.File file && file.isFile()) files++;
            queue.addAll(item.getChildren());
        }
        filesValue.setText(Integer.toString(files));
    }

    private void refreshTableCounters() {
        int count = 0;
        int high = 0;
        if (findingsTable != null && findingsTable.getItems() != null) {
            for (Object item : findingsTable.getItems()) {
                count++;
                if (item instanceof Vulnerability vulnerability) {
                    String severity = vulnerability.getSeverity();
                    if (severity != null && ("HIGH".equalsIgnoreCase(severity.strip())
                            || "CRITICAL".equalsIgnoreCase(severity.strip()))) high++;
                }
            }
        }
        findingsValue.setText(Integer.toString(count));
        highValue.setText(Integer.toString(high));
        tableStatus.setText("Текущая таблица: " + count + " находок");
    }

    private void refreshModelLabel() {
        Object value = modelSelector == null ? null : modelSelector.getValue();
        modelStatus.setText("Модель: " + (value == null ? "не выбрана" : value.toString()));
    }

    private void connectWebViews() {
        visit(root, node -> {
            if (!(node instanceof WebView web)) return;
            webViews.add(web);
            web.getEngine().getLoadWorker().stateProperty().addListener((obs, oldValue, newValue) -> {
                if (newValue == Worker.State.SUCCEEDED) {
                    // Pages are replaced by MainController.loadContent after every message.
                    applyWebStyle(web);
                }
            });
        });
    }

    private void refreshWebViews() {
        for (WebView web : webViews) applyWebStyle(web);
    }

    private boolean isDark() {
        return scene.getStylesheets().stream()
                .anyMatch(url -> url.contains("dark-theme.css"));
    }

    private void applyWebStyle(WebView web) {
        boolean dark = isDark();
        web.setPageFill(Color.web(dark ? "#202b3d" : "#ffffff"));
        String file = dark ? WEB_DARK : WEB_LIGHT;
        String css = dark ? webDarkCss : webLightCss;
        URL url = UiDashboardEnhancer.class.getResource(file);
        if (url != null) {
            web.getEngine().setUserStyleSheetLocation(url.toExternalForm());
        }
        try {
            // Fallback for loaded documents and older WebKit versions.
            String javascript = "(function(){var d=document; if(!d||!d.documentElement)return;"
                    + "var s=d.getElementById('csa-dashboard-html-style');"
                    + "if(!s){s=d.createElement('style');s.id='csa-dashboard-html-style';"
                    + "(d.head||d.documentElement).appendChild(s);}"
                    + "s.textContent='" + escapeJs(css) + "';})();";
            web.getEngine().executeScript(javascript);
        } catch (RuntimeException ignored) {
            // Document may not be ready; load worker listener retries after SUCCEEDED.
        }
    }

    private static String escapeJs(String input) {
        return input.replace("\\", "\\\\").replace("'", "\\'")
                .replace("\r", "\\r").replace("\n", "\\n")
                .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
    }

    private static String readResource(String path) {
        try (InputStream in = UiDashboardEnhancer.class.getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("Не найден стиль WebView: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Ошибка чтения CSS: " + path, ex);
        }
    }

    private static <T extends Node> T findById(Node start, String id, Class<T> type) {
        final ArrayList<T> matches = new ArrayList<>();
        visit(start, node -> {
            if (id.equals(node.getId()) && type.isInstance(node)) matches.add(type.cast(node));
        });
        return matches.isEmpty() ? null : matches.getFirst();
    }

    private static void visit(Node start, Consumer<Node> visitor) {
        Set<Node> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        visitRecursive(start, visitor, seen);
    }

    private static void visitRecursive(Node node, Consumer<Node> visitor, Set<Node> seen) {
        if (node == null || !seen.add(node)) return;
        visitor.accept(node);
        if (node instanceof TabPane tabs) {
            for (Tab tab : tabs.getTabs()) visitRecursive(tab.getContent(), visitor, seen);
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) visitRecursive(child, visitor, seen);
        }
    }
}
