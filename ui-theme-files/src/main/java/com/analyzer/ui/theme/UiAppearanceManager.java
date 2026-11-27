package com.analyzer.ui.theme;

import javafx.application.Platform;
import javafx.collections.ListChangeListener;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.binding.Bindings;
import javafx.concurrent.Worker;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeView;
import javafx.scene.control.TreeCell;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import javafx.stage.Window;
import javafx.util.Callback;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.function.Consumer;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.prefs.Preferences;

/**
 * UI-only enhancement: runtime themes and responsive JavaFX toolbars.
 * Intentionally independent from scanning, LLM, report and fix services.
 */
public final class UiAppearanceManager {

    private static final String LIGHT = "light";
    private static final String DARK = "dark";
    private static final String PREF_KEY = "colorTheme";
    private static final double NARROW_LAYOUT = 860.0;

    private final Stage primaryStage;
    private final VBox root;
    private final Scene scene;
    private final String lightStylesheet;
    private final String darkStylesheet;
    private final List<WebView> webViews = new ArrayList<>();
    private final Set<Scene> preparedDialogs = Collections.newSetFromMap(new IdentityHashMap<>());
    private String theme;
    private final StringProperty themeProperty = new SimpleStringProperty();

    private UiAppearanceManager(Stage primaryStage, VBox root) {
        this.primaryStage = primaryStage;
        this.root = root;
        this.scene = primaryStage.getScene();
        this.lightStylesheet = stylesheet("/styles/light-theme.css");
        this.darkStylesheet = stylesheet("/styles/dark-theme.css");
        this.theme = readPreference();
        this.themeProperty.set(this.theme);
    }

    public static void install(Stage stage, Parent loadedRoot) {
        if (!(loadedRoot instanceof VBox root)) {
            throw new IllegalArgumentException("Ожидался VBox в main-view.fxml");
        }
        if (stage.getScene() == null) {
            throw new IllegalArgumentException("Scene должна быть установлена до темы");
        }
        new UiAppearanceManager(stage, root).install();
    }

    private void install() {
        root.getStyleClass().add("csa-app");
        stripFixedColors(root);
        decorateButtons(root);
        preserveTreeCellContrast();
        installResponsiveLayout();
        addThemeChooser();
        collectWebViews(root);

        applyThemeToAllWindows();
        Window.getWindows().addListener((ListChangeListener<Window>) change -> {
            while (change.next()) {
                if (change.wasAdded()) {
                    for (Window window : change.getAddedSubList()) {
                        if (window.getScene() != null) {
                            styleScene(window.getScene());
                        }
                        window.sceneProperty().addListener((obs, oldScene, newScene) -> {
                            if (newScene != null) styleScene(newScene);
                        });
                    }
                }
            }
        });
        primaryStage.setMinWidth(640);
        primaryStage.setMinHeight(520);
        if (!Double.isFinite(primaryStage.getWidth()) || primaryStage.getWidth() < 1050) {
            primaryStage.setWidth(1100);
        }
        if (!Double.isFinite(primaryStage.getHeight()) || primaryStage.getHeight() < 760) {
            primaryStage.setHeight(760);
        }
    }

    private static String stylesheet(String path) {
        URL url = UiAppearanceManager.class.getResource(path);
        if (url == null) throw new IllegalStateException("Не найден CSS: " + path);
        return url.toExternalForm();
    }

    private void addThemeChooser() {
        HBox header = new HBox(12);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(2, 4, 7, 4));
        header.getStyleClass().add("csa-header");

        Label brand = new Label("🛡 Code Security Analyzer");
        brand.getStyleClass().add("csa-brand");
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        Label caption = new Label("Тема:");
        caption.getStyleClass().add("csa-theme-caption");
        ComboBox<String> chooser = new ComboBox<>();
        chooser.getItems().addAll("Светлая", "Тёмная");
        chooser.setValue(DARK.equals(theme) ? "Тёмная" : "Светлая");
        chooser.setPrefWidth(135);
        chooser.setMinWidth(110);
        chooser.setOnAction(e -> selectTheme("Тёмная".equals(chooser.getValue()) ? DARK : LIGHT));

        header.getChildren().addAll(brand, spacer, caption, chooser);
        root.getChildren().add(0, header);
    }

    private void selectTheme(String requestedTheme) {
        theme = DARK.equals(requestedTheme) ? DARK : LIGHT;
        themeProperty.set(theme);
        try {
            Preferences.userNodeForPackage(UiAppearanceManager.class).put(PREF_KEY, theme);
        } catch (SecurityException ignored) {
            // A restricted OS account can still use themes for the current session.
        }
        applyThemeToAllWindows();
    }

    private static String readPreference() {
        try {
            String saved = Preferences.userNodeForPackage(UiAppearanceManager.class)
                    .get(PREF_KEY, LIGHT);
            return DARK.equals(saved) ? DARK : LIGHT;
        } catch (SecurityException ignored) {
            return LIGHT;
        }
    }

    private void applyThemeToAllWindows() {
        styleScene(scene);
        for (Window window : Window.getWindows()) {
            if (window.getScene() != null) styleScene(window.getScene());
        }
        recolorExplicitLabels(root);
        for (WebView web : webViews) applyWebStyle(web);
    }

    private void styleScene(Scene target) {
        if (target != scene && preparedDialogs.add(target) && target.getRoot() != null) {
            // Dialogs have their own Scene and sometimes hard-coded light styling.
            stripFixedColors(target.getRoot());
        }
        target.getStylesheets().removeAll(lightStylesheet, darkStylesheet);
        target.getStylesheets().add(DARK.equals(theme) ? darkStylesheet : lightStylesheet);
        if (target != scene && target.getRoot() != null) {
            recolorExplicitLabels(target.getRoot());
        }
    }

    /**
     * FXML uses many inline hard-coded white backgrounds and text colors.
     * Remove only palette declarations, preserving padding, font weight,
     * border radii and other layout declarations.
     */
    static String withoutHardcodedPalette(String inlineStyle) {
        if (inlineStyle == null || inlineStyle.isBlank()) return "";
        Set<String> forbidden = Set.of(
                "-fx-background-color", "-fx-text-fill", "-fx-border-color",
                "-fx-control-inner-background", "-fx-text-background-color");
        List<String> retained = new ArrayList<>();
        for (String declaration : inlineStyle.split(";")) {
            String candidate = declaration.strip();
            if (candidate.isEmpty()) continue;
            int colon = candidate.indexOf(':');
            String name = colon < 0 ? "" : candidate.substring(0, colon).strip().toLowerCase(Locale.ROOT);
            if (!forbidden.contains(name)) retained.add(candidate);
        }
        return String.join("; ", retained);
    }

    private static void stripFixedColors(Node root) {
        visit(root, node -> {
            String inline = node.getStyle();
            if (inline != null && !inline.isBlank()) {
                node.setStyle(withoutHardcodedPalette(inline));
            }
        });
    }

    private void recolorExplicitLabels(Node rootNode) {
        Color color = DARK.equals(theme) ? Color.web("#e8edf5") : Color.web("#223047");
        visit(rootNode, node -> {
            if (node instanceof Label label) {
                if (label.getStyleClass().contains("csa-brand")) {
                    label.setTextFill(DARK.equals(theme) ? Color.web("#b1c6ff") : Color.web("#2257a5"));
                } else if (label.getText() != null && label.getText().startsWith("Найденные уязвимости")) {
                    label.setTextFill(DARK.equals(theme) ? Color.web("#ff9a9a") : Color.web("#b72836"));
                } else {
                    label.setTextFill(color);
                }
            } else if (node instanceof CheckBox checkBox) {
                checkBox.setTextFill(color);
            }
        });
    }

    private static void decorateButtons(Node rootNode) {
        visit(rootNode, node -> {
            if (!(node instanceof Button button)) return;
            String id = button.getId();
            if (id == null) return;
            switch (id) {
                case "scanButton", "startBenchmarkButton" -> button.getStyleClass().add("csa-primary");
                case "clearButton", "clearGeneralChatButton" -> button.getStyleClass().add("csa-danger");
                case "exportPdfButton", "sendPromptButton", "sendGeneralChatPromptButton", "agentStartButton" ->
                        button.getStyleClass().add("csa-success");
                case "fixCurrentFileButton", "fixAllButton" -> button.getStyleClass().add("csa-accent");
                case "selectFolderButton", "agentSelectFolderButton", "selectBenchmarkFolderButton" ->
                        button.getStyleClass().add("csa-secondary");
                default -> { }
            }
        });
    }

    // JavaFX Tab content is not always part of the active scene-graph until
    // selected; traverse it explicitly to style ALL four tabs immediately.
    private static void visit(Node start, Consumer<Node> visitor) {
        Set<Node> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        visitRecursive(start, visitor, visited);
    }

    private static void visitRecursive(Node node, Consumer<Node> visitor, Set<Node> seen) {
        if (node == null || !seen.add(node)) return;
        visitor.accept(node);
        if (node instanceof TabPane tabs) {
            for (Tab tab : tabs.getTabs()) {
                visitRecursive(tab.getContent(), visitor, seen);
            }
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) {
                visitRecursive(child, visitor, seen);
            }
        }
    }

    /**
     * Existing MainController sets inline colors on check-box tree cells.
     * Explicit textFill binding keeps file names readable on both themes,
     * while preserving red/green state indicators.
     */
    @SuppressWarnings("unchecked")
    private void preserveTreeCellContrast() {
        visit(root, node -> {
            if (!(node instanceof TreeView<?> treeView)) return;
            TreeView<Object> tree = (TreeView<Object>) treeView;
            Callback<TreeView<Object>, TreeCell<Object>> original = tree.getCellFactory();
            if (original == null) return;
            tree.setCellFactory(view -> {
                TreeCell<Object> cell = original.call(view);
                cell.textFillProperty().bind(Bindings.createObjectBinding(() -> {
                    String css = cell.getStyle() == null ? "" : cell.getStyle().toLowerCase(Locale.ROOT);
                    boolean dark = DARK.equals(themeProperty.get());
                    if (cell.isSelected()) return Color.WHITE;
                    if (css.contains("#c0392b")) return Color.web(dark ? "#ff9292" : "#b72836");
                    if (css.contains("#27ae60")) return Color.web(dark ? "#75d6a0" : "#168553");
                    return Color.web(dark ? "#e8edf5" : "#223047");
                }, themeProperty, cell.styleProperty(), cell.selectedProperty()));
                return cell;
            });
        });
    }

    private void installResponsiveLayout() {
        TabPane tabs = null;
        for (Node child : root.getChildren()) {
            if (child instanceof TabPane pane) {
                tabs = pane;
                break;
            }
        }
        if (tabs == null || tabs.getTabs().size() < 4) return;

        if (tabs.getTabs().get(0).getContent() instanceof VBox scanPane) {
            wrapToolbar(scanPane, 0, true);
            wrapToolbar(scanPane, 1, false);
            for (Node node : scanPane.getChildren()) {
                if (node instanceof SplitPane split) {
                    scene.widthProperty().addListener((obs, oldWidth, width) ->
                            adaptSplit(split, width.doubleValue()));
                    adaptSplit(split, scene.getWidth());
                    break;
                }
            }
            visit(scanPane, node -> {
                if (node instanceof TableView<?> table) {
                    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
                }
            });
        }
        if (tabs.getTabs().get(1).getContent() instanceof VBox chatPane) {
            wrapToolbar(chatPane, 0, false);
        }
        if (tabs.getTabs().get(3).getContent() instanceof VBox benchmarkPane) {
            wrapToolbar(benchmarkPane, 0, false);
        }
    }

    private static void adaptSplit(SplitPane split, double sceneWidth) {
        Orientation desired = sceneWidth < NARROW_LAYOUT
                ? Orientation.VERTICAL : Orientation.HORIZONTAL;
        if (split.getOrientation() != desired) {
            split.setOrientation(desired);
            Platform.runLater(() -> split.setDividerPositions(
                    desired == Orientation.VERTICAL ? 0.28 : 0.26));
        }
    }

    /** FlowPane wraps toolbar buttons when the window becomes narrow. */
    private static void wrapToolbar(VBox container, int index, boolean equalButtonWidths) {
        if (index >= container.getChildren().size()) return;
        Node old = container.getChildren().get(index);
        if (!(old instanceof HBox row)) return;
        FlowPane flow = new FlowPane(Orientation.HORIZONTAL);
        flow.setHgap(Math.max(8, row.getSpacing()));
        flow.setVgap(8);
        flow.setAlignment(Pos.CENTER_LEFT);
        flow.setMaxWidth(Double.MAX_VALUE);
        flow.setPadding(row.getPadding());
        flow.getStyleClass().add("csa-toolbar");

        List<Node> contents = new ArrayList<>(row.getChildren());
        row.getChildren().clear();
        flow.getChildren().addAll(contents);
        container.getChildren().set(index, flow);

        if (equalButtonWidths) {
            for (Node child : contents) {
                if (child instanceof Button button) {
                    button.setMinWidth(0);
                    button.setMaxWidth(Double.MAX_VALUE);
                    button.prefWidthProperty().bind(javafx.beans.binding.Bindings.createDoubleBinding(() -> {
                        double usable = Math.max(1, flow.getWidth() - flow.getPadding().getLeft()
                                - flow.getPadding().getRight());
                        int columns = Math.max(1, (int) Math.floor((usable + flow.getHgap()) / 222.0));
                        columns = Math.min(columns, contents.size());
                        return Math.max(120, (usable - (columns - 1) * flow.getHgap()) / columns - 1);
                    }, flow.widthProperty()));
                }
            }
        } else {
            for (Node child : contents) {
                if (child instanceof Label label) {
                    label.setWrapText(true);
                    label.maxWidthProperty().bind(flow.widthProperty().subtract(18));
                }
            }
        }
    }

    private void collectWebViews(Node rootNode) {
        visit(rootNode, node -> {
            if (!(node instanceof WebView web)) return;
            webViews.add(web);
            web.getEngine().getLoadWorker().stateProperty().addListener((obs, oldState, newState) -> {
                if (newState == Worker.State.SUCCEEDED) applyWebStyle(web);
            });
        });
    }

    private void applyWebStyle(WebView web) {
        boolean dark = DARK.equals(theme);
        web.setPageFill(Color.web(dark ? "#181f2b" : "#ffffff"));
        String css = dark
                ? "html,body{background:#181f2b!important;color:#e8edf5!important;}"
                    + "a{color:#86b7ff!important;}pre,code{color:#d3e3ff!important;}"
                    + "input,textarea{background:#263247!important;color:#e8edf5!important;}"
                : "html,body{background:#ffffff!important;color:#223047!important;}"
                    + "a{color:#2257a5!important;}pre,code{color:#253c68!important;}";
        try {
            String js = "(function(){var s=document.getElementById('csa-web-theme');"
                    + "if(!s){s=document.createElement('style');s.id='csa-web-theme';"
                    + "(document.head||document.documentElement).appendChild(s);}"
                    + "s.textContent='" + css.replace("\\", "\\\\").replace("'", "\\'") + "';})();";
            web.getEngine().executeScript(js);
        } catch (RuntimeException ignored) {
            // WebView may not have finished loading. The SUCCEEDED listener will retry.
        }
    }
}
