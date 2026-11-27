package com.analyzer.ui.theme;

import javafx.animation.PauseTransition;
import javafx.application.Platform;
import javafx.collections.ListChangeListener;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.CheckBoxTreeItem;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.File;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;

/**
 * UI-only finishing layer for the installed theme/dashboard/icons/contrast stack.
 * The source tree is NEVER modified on disk. Filtering creates temporary display
 * TreeItems; the original tree is retained for restoration and selection state.
 * The scan command intentionally uses only currently VISIBLE checked files while
 * filtering is active. This behavior is disclosed next to the filter controls.
 */
public final class UiPolishV5 {
    private static final Set<String> SOURCE_SUFFIXES = Set.of(
            ".java", ".kt", ".scala", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
            ".py", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".php", ".rb",
            ".go", ".rs", ".cs", ".sql");
    private static final Set<String> GENERATED_FOLDERS = Set.of(
            ".git", ".idea", ".venv", ".venv-semgrep", "target", "build",
            "dist", "node_modules", "__pycache__", "ui-theme-backup", "fix-validation",
            "ui-theme-files", "ui-dashboard-files", "ui-icons-files", "ui-v4-files",
            "ui-v5-files");

    private final Stage stage;
    private final Parent root;
    private final Scene scene;
    private TreeView<File> fileTree;
    private boolean treeConnected;
    private final TextField search = new TextField();
    private final CheckBox onlySources = new CheckBox("Только исходники");
    private final Label filterHint = new Label("Фильтр ограничивает файлы, доступные для выбора и запуска анализа.");
    private final Label found = new Label();
    private final PauseTransition debounce = new PauseTransition(Duration.millis(170));
    private final String lightCss = stylesheet("/styles/ui-v5-light.css");
    private final String darkCss = stylesheet("/styles/ui-v5-dark.css");
    private TreeItem<File> originalRoot;
    private boolean internalRootChange;
    private boolean cssScheduled;
    private Label filesMetric;
    private Label filesNote;

    private UiPolishV5(Stage stage, Parent root) {
        this.stage = stage;
        this.root = root;
        this.scene = stage.getScene();
        this.fileTree = findById(root, "fileTreeView", TreeView.class);
    }

    public static void install(Stage stage, Parent root) {
        if (stage == null || stage.getScene() == null || root == null) {
            throw new IllegalArgumentException("UiPolishV5: отсутствует окно или Scene");
        }
        new UiPolishV5(stage, root).install();
    }

    private void install() {
        if (Boolean.TRUE.equals(root.getProperties().put("csa-ui-v5-installed", true))) return;
        root.getStyleClass().add("csa-ui-v5");
        locateFileMetric();
        styleResizablePanels();
        scene.getStylesheets().addListener((ListChangeListener<String>) c -> scheduleCssRefresh());
        applyThemeStylesheet();
        stage.setMinWidth(Math.max(stage.getMinWidth(), 700));
        stage.setMinHeight(Math.max(stage.getMinHeight(), 560));
        // FXML Tab content can appear only after the stage becomes visible.
        // Never call createFilterControls while fileTree is null.
        stage.showingProperty().addListener((obs, oldValue, showing) -> {
            if (showing) Platform.runLater(this::connectTreeIfAvailable);
        });
        Platform.runLater(this::connectTreeIfAvailable);
    }

    private void connectTreeIfAvailable() {
        if (fileTree == null) fileTree = resolveFileTree();
        if (fileTree == null) {
            if (stage.isShowing()) {
                System.err.println("UI filter: fileTreeView not found; filtering remains disabled.");
            }
            return;
        }
        if (!treeConnected) {
            treeConnected = true;
            originalRoot = fileTree.getRoot();
            fileTree.rootProperty().addListener((obs, before, after) -> {
                if (internalRootChange) return;
                originalRoot = after;
                if (filterActive()) debounce.playFromStart();
                else refreshCounter();
            });
            search.textProperty().addListener((obs, oldValue, newValue) -> debounce.playFromStart());
            onlySources.selectedProperty().addListener((obs, oldValue, newValue) -> applyFilter());
            debounce.setOnFinished(event -> applyFilter());
        }
        createFilterControls();
        refreshCounter();
    }

    @SuppressWarnings("unchecked")
    private TreeView<File> resolveFileTree() {
        TreeView<File> byId = findById(root, "fileTreeView", TreeView.class);
        if (byId != null) return byId;
        Node node = root.lookup("#fileTreeView");
        if (node instanceof TreeView<?> tree) return (TreeView<File>) tree;
        // Some FXML/layout wrappers do not expose the fx:id as a CSS id.
        // Fallback only when exactly one TreeView exists in this window.
        List<TreeView<?>> trees = new ArrayList<>();
        visit(root, candidate -> {
            if (candidate instanceof TreeView<?> tree) trees.add(tree);
        });
        return trees.size() == 1 ? (TreeView<File>) trees.getFirst() : null;
    }

    private void createFilterControls() {
        if (fileTree == null || fileTree.getParent() == null) return;
        // UI Filter v7: look through intervening layout wrappers
        Node slot = fileTree;
        Parent parent = fileTree.getParent();
        while (parent != null && !(parent instanceof VBox)) {
            slot = parent;
            parent = parent.getParent();
        }
        if (!(parent instanceof VBox column)) return;
        if (column.getChildren().stream().anyMatch(n -> n.getStyleClass().contains("csa-tree-filter"))) return;

        VBox panel = new VBox(5);
        panel.getStyleClass().add("csa-tree-filter");
        search.setPromptText("Поиск файла или папки...");
        search.getStyleClass().add("csa-tree-search");
        search.setMinWidth(60);
        HBox.setHgrow(search, Priority.ALWAYS);
        Button reset = new Button("×");
        reset.getStyleClass().add("csa-tree-reset");
        reset.setTooltip(new Tooltip("Сбросить поиск и фильтр"));
        reset.setOnAction(event -> {
            search.clear();
            onlySources.setSelected(false);
            applyFilter();
        });
        HBox searchLine = new HBox(5, search, reset);
        searchLine.setAlignment(Pos.CENTER_LEFT);
        onlySources.getStyleClass().add("csa-only-sources");
        onlySources.setTooltip(new Tooltip("Показывать поддерживаемые исходные файлы, скрыв служебные каталоги"));
        filterHint.setWrapText(true);
        filterHint.getStyleClass().add("csa-filter-hint");
        found.getStyleClass().add("csa-filter-count");
        panel.getChildren().addAll(searchLine, onlySources, found, filterHint);
        int index = column.getChildren().indexOf(slot);
        column.getChildren().add(Math.max(0, index), panel);
        VBox.setVgrow(fileTree, Priority.ALWAYS);
    }

    private boolean filterActive() {
        return onlySources.isSelected() || !search.getText().isBlank();
    }

    private void applyFilter() {
        if (fileTree == null || originalRoot == null) {
            refreshCounter();
            return;
        }
        TreeItem<File> viewRoot;
        if (!filterActive()) {
            viewRoot = originalRoot;
        } else {
            String term = search.getText().strip().toLowerCase(Locale.ROOT);
            viewRoot = project(originalRoot, term, onlySources.isSelected(), false);
            if (viewRoot == null) {
                // Keep the original root name when the result is empty.
                viewRoot = new CheckBoxTreeItem<>(originalRoot.getValue());
            }
            viewRoot.setExpanded(true);
        }
        if (fileTree.getRoot() != viewRoot) {
            internalRootChange = true;
            try {
                fileTree.setRoot(viewRoot);
                fileTree.getSelectionModel().clearSelection();
            } finally {
                internalRootChange = false;
            }
        }
        refreshCounter();
    }

    /** Creates a view projection without removing or reparenting an original node. */
    private TreeItem<File> project(TreeItem<File> source, String term, boolean sourcesOnly,
                                    boolean parentMatches) {
        if (source == null || source.getValue() == null) return null;
        File file = source.getValue();
        boolean directory = file.isDirectory();
        if (sourcesOnly && directory && GENERATED_FOLDERS.contains(file.getName().toLowerCase(Locale.ROOT))) {
            return null;
        }
        String filename = file.getName().toLowerCase(Locale.ROOT);
        boolean matches = term.isBlank() || filename.contains(term) || parentMatches;
        if (!directory) {
            if (!matches || (sourcesOnly && !isSource(filename))) return null;
            return makeViewNode(source);
        }
        CheckBoxTreeItem<File> copy = makeViewNode(source);
        boolean matchingDir = !term.isBlank() && (filename.contains(term) || parentMatches);
        for (TreeItem<File> child : source.getChildren()) {
            TreeItem<File> candidate = project(child, term, sourcesOnly, matchingDir);
            if (candidate != null) copy.getChildren().add(candidate);
        }
        if (source == originalRoot || !copy.getChildren().isEmpty()) {
            copy.setExpanded(term.isBlank() ? source.isExpanded() : true);
            return copy;
        }
        return null;
    }

    /**
     * Copy items retain original selection when rebuilding the view. Checked
     * visible folders select visible descendants as the main UI expects; hidden
     * leaves aren't deleted or changed by text filtering itself.
     */
    private static CheckBoxTreeItem<File> makeViewNode(TreeItem<File> source) {
        CheckBoxTreeItem<File> copy = new CheckBoxTreeItem<>(source.getValue());
        copy.setIndependent(true);
        copy.setExpanded(source.isExpanded());
        if (source instanceof CheckBoxTreeItem<?> checked) copy.setSelected(checked.isSelected());
        copy.selectedProperty().addListener((obs, oldValue, newValue) -> {
            if (source instanceof CheckBoxTreeItem<?> original) {
                original.setSelected(newValue);
            }
            if (copy.getValue() != null && copy.getValue().isDirectory()) {
                for (TreeItem<File> descendant : copy.getChildren()) {
                    if (descendant instanceof CheckBoxTreeItem<File> check) {
                        check.setSelected(newValue);
                    }
                }
            }
        });
        return copy;
    }

    private static boolean isSource(String lowerName) {
        for (String suffix : SOURCE_SUFFIXES) {
            if (lowerName.endsWith(suffix)) return true;
        }
        return false;
    }

    private void locateFileMetric() {
        visit(root, node -> {
            if (!(node instanceof VBox card) || !card.getStyleClass().contains("csa-metric-card")) return;
            Label title = null, value = null, note = null;
            for (Node child : card.getChildren()) {
                if (!(child instanceof Label label)) continue;
                if (label.getStyleClass().contains("csa-metric-heading")) title = label;
                if (label.getStyleClass().contains("csa-metric-value")) value = label;
                if (label.getStyleClass().contains("csa-metric-note")) note = label;
            }
            if (title != null && title.getText().contains("ФАЙЛОВ")) {
                filesMetric = value;
                filesNote = note;
            }
        });
    }

    private void refreshCounter() {
        if (fileTree == null) return;
        int n = countFiles(fileTree.getRoot());
        if (filesMetric != null) filesMetric.setText(Integer.toString(n));
        if (filesNote != null) filesNote.setText(filterActive()
                ? "Отображаемые файлы (не число проверенных)"
                : "Все файлы дерева (не число проверенных)");
        found.setText(filterActive() ? "Показано файлов: " + n : "Файлов в дереве: " + n);
    }

    private static int countFiles(TreeItem<File> root) {
        if (root == null) return 0;
        int total = 0;
        ArrayDeque<TreeItem<File>> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty()) {
            TreeItem<File> item = queue.removeFirst();
            if (item.getValue() != null && item.getValue().isFile()) total++;
            queue.addAll(item.getChildren());
        }
        return total;
    }

    private void styleResizablePanels() {
        visit(root, node -> {
            if (node instanceof SplitPane pane) {
                if (!pane.getStyleClass().contains("csa-resizable-split")) {
                    pane.getStyleClass().add("csa-resizable-split");
                }
                for (Node item : pane.getItems()) {
                    if (item instanceof javafx.scene.layout.Region region) {
                        region.setMinWidth(0);
                        region.setMinHeight(0);
                    }
                }
            }
            if (node instanceof TableView<?> table && "vulnerabilitiesTable".equals(table.getId())) {
                table.setFixedCellSize(31);
            }
        });
    }

    private void scheduleCssRefresh() {
        if (cssScheduled) return;
        cssScheduled = true;
        Platform.runLater(() -> {
            cssScheduled = false;
            applyThemeStylesheet();
        });
    }

    private void applyThemeStylesheet() {
        String currentTheme = scene.getStylesheets().stream().anyMatch(s -> s.contains("dark-theme.css"))
                ? darkCss : lightCss;
        var sheets = scene.getStylesheets();
        if (sheets.size() > 0 && sheets.get(sheets.size() - 1).equals(currentTheme)
                && !sheets.contains(currentTheme.equals(lightCss) ? darkCss : lightCss)) return;
        sheets.removeAll(lightCss, darkCss);
        sheets.add(currentTheme);
    }

    private static String stylesheet(String resource) {
        URL url = UiPolishV5.class.getResource(resource);
        if (url == null) throw new IllegalStateException("Не найден ресурс " + resource);
        return url.toExternalForm();
    }

    @SuppressWarnings("unchecked")
    private static <T> T findById(Node root, String id, Class<T> type) {
        final Object[] result = {null};
        visit(root, node -> {
            if (result[0] == null && id.equals(node.getId()) && type.isInstance(node)) result[0] = node;
        });
        return (T) result[0];
    }

    private static void visit(Node root, Consumer<Node> consumer) {
        Set<Node> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        visitNode(root, consumer, seen);
    }

    private static void visitNode(Node node, Consumer<Node> consumer, Set<Node> seen) {
        if (node == null || !seen.add(node)) return;
        consumer.accept(node);
        if (node instanceof TabPane tabs) {
            for (Tab tab : tabs.getTabs()) visitNode(tab.getContent(), consumer, seen);
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) visitNode(child, consumer, seen);
        }
    }
}
