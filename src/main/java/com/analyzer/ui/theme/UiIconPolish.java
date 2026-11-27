package com.analyzer.ui.theme;

import com.analyzer.ui.UiLanguage;
import javafx.animation.ScaleTransition;
import javafx.application.Platform;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;
import javafx.scene.control.TreeCell;
import javafx.scene.control.TreeView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;
import javafx.stage.Stage;
import javafx.util.Callback;
import javafx.util.Duration;
import javafx.scene.image.Image;

import java.io.File;
import java.io.InputStream;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Presentation-only finishing layer. Installed after UiAppearanceManager and
 * UiDashboardEnhancer. Uses vector JavaFX shapes; no external icon libraries,
 * network requests, service changes, generated-code execution or file writes.
 */
public final class UiIconPolish {
    private final Stage stage;
    private final VBox root;

    private UiIconPolish(Stage stage, VBox root) {
        this.stage = stage;
        this.root = root;
    }

    public static void install(Stage stage, Parent parent) {
        if (!(parent instanceof VBox root) || stage.getScene() == null) {
            throw new IllegalArgumentException("UI Icons: ожидается VBox и созданная Scene");
        }
        new UiIconPolish(stage, root).install();
    }

    private void install() {
        applyWindowIcon();
        stage.setTitle("Code Security Analyzer — локальный аудит кода");
        installBrand();
        installTabs();
        installButtons();
        installThemeSelector();
        installDashboardIcons();
        installFooterIcons();
        installTreeIcons();
        installPlaceholders();
    }

    private void applyWindowIcon() {
        try (InputStream stream = UiIconPolish.class.getResourceAsStream("/images/app-shield.png")) {
            if (stream != null) {
                stage.getIcons().clear();
                stage.getIcons().add(new Image(stream));
            }
        } catch (Exception ignored) {
            // A missing decorative icon must never prevent the analyzer launching.
        }
    }

    private void installBrand() {
        visit(root, node -> {
            if (!(node instanceof Label label) || !label.getStyleClass().contains("csa-brand")) return;
            label.setText("Code Security Analyzer");
            label.setGraphic(icon("shield-check", 22));
            label.setGraphicTextGap(10);
        });
    }

    private void installTabs() {
        visit(root, node -> {
            if (!(node instanceof TabPane tabs)) return;
            String[] labels = { "Анализ кода", "Чат с ИИ", "ИИ-агент генерации", "Бенчмарк" };
            String[] symbols = { "shield-search", "message", "sparkles", "chart" };
            for (int i = 0; i < Math.min(tabs.getTabs().size(), labels.length); i++) {
                Tab tab = tabs.getTabs().get(i);
                tab.setText(labels[i]);
                tab.setGraphic(icon(symbols[i], 17));
                tab.setTooltip(new Tooltip(labels[i]));
            }
        });
    }

    private record ButtonSpec(String text, String icon, String hint) {}

    private static final Map<String, ButtonSpec> BUTTONS = Map.ofEntries(
            Map.entry("selectFolderButton", new ButtonSpec("Выбрать папку", "folder-open", "Выбрать проект для анализа")),
            Map.entry("clearButton", new ButtonSpec("Очистить", "trash", "Очистить загруженный проект и результаты")),
            Map.entry("scanButton", new ButtonSpec("Запустить анализ выбранных", "shield-search", "Запустить LLM и Semgrep для выбранных файлов")),
            Map.entry("pasteCodeButton", new ButtonSpec("Из буфера (Ctrl+V)", "clipboard", "Анализ исходного кода из буфера")),
            Map.entry("fixAllButton", new ButtonSpec("Предложения для 5 файлов", "sparkles", "Получить предложения исправлений для выбранных файлов")),
            Map.entry("exportPdfButton", new ButtonSpec("Сохранить PDF", "file-text", "Создать PDF-отчёт по результатам")),
            Map.entry("importSemgrepButton", new ButtonSpec("Импорт Semgrep JSON", "file-input", "Импортировать существующий JSON-отчёт Semgrep")),
            Map.entry("exportResultsButton", new ButtonSpec("Экспорт JSON/CSV", "download", "Экспортировать результаты анализа")),
            Map.entry("fixCurrentFileButton", new ButtonSpec("Предложить исправление", "wrench", "Получить черновик исправления текущего файла")),
            Map.entry("sendPromptButton", new ButtonSpec("Отправить", "send", "Отправить вопрос об уязвимости")),
            Map.entry("refreshModelsButton", new ButtonSpec("Обновить список", "refresh", "Обновить список локальных моделей Ollama")),
            Map.entry("clearGeneralChatButton", new ButtonSpec("Сбросить чат", "trash", "Очистить историю общего чата")),
            Map.entry("sendGeneralChatPromptButton", new ButtonSpec("Отправить", "send", "Отправить сообщение модели")),
            Map.entry("agentSelectFolderButton", new ButtonSpec("Обзор...", "folder-open", "Выбрать рабочую папку генератора")),
            Map.entry("agentStartButton", new ButtonSpec("Запустить генерацию проекта", "play", "Запустить работу агента генерации")),
            Map.entry("selectBenchmarkFolderButton", new ButtonSpec("Тестовая папка", "folder-open", "Выбрать папку для бенчмарка")),
            Map.entry("startBenchmarkButton", new ButtonSpec("Запустить бенчмарк", "chart", "Начать сравнение моделей на выбранных файлах"))
    );

    private void installButtons() {
        visit(root, node -> {
            if (!(node instanceof Button button)) return;
            ButtonSpec spec = BUTTONS.get(button.getId());
            if (spec == null) return;
            button.setText(spec.text());
            button.setGraphic(icon(spec.icon(), 18));
            button.setGraphicTextGap(9);
            button.setContentDisplay(javafx.scene.control.ContentDisplay.LEFT);
            if (button.getTooltip() == null) button.setTooltip(new Tooltip(spec.hint()));
            button.getStyleClass().add("csa-polished-button");
            addHoverMotion(button);
        });
    }

    private static void addHoverMotion(Button button) {
        // Event filters preserve existing onAction, hover listeners and keyboard input.
        button.addEventHandler(javafx.scene.input.MouseEvent.MOUSE_ENTERED, event -> {
            if (!button.isDisabled()) animate(button, 1.018);
        });
        button.addEventHandler(javafx.scene.input.MouseEvent.MOUSE_EXITED, event -> animate(button, 1.0));
    }

    private static void animate(Node node, double scale) {
        ScaleTransition animation = new ScaleTransition(Duration.millis(105), node);
        animation.setToX(scale);
        animation.setToY(scale);
        animation.play();
    }

    @SuppressWarnings("unchecked")
    private void installThemeSelector() {
        visit(root, node -> {
            if (!(node instanceof ComboBox<?> raw)) return;
            ComboBox<String> combo = (ComboBox<String>) raw;
            if (combo.getItems().size() != 2 || !combo.getItems().containsAll(List.of("Светлая", "Тёмная"))) return;
            combo.setButtonCell(new ThemeCell());
            combo.setCellFactory(list -> new ThemeCell());
            combo.setTooltip(new Tooltip("Переключить оформление: светлая или тёмная тема"));
        });
    }

    private static final class ThemeCell extends ListCell<String> {
        @Override
        protected void updateItem(String item, boolean empty) {
            super.updateItem(item, empty);
            textProperty().unbind();
            if (empty || item == null) {
                setText(null);
                setGraphic(null);
            } else {
                textProperty().bind(UiLanguage.localized(() -> UiLanguage.tr(item)));
                setGraphic(icon("Тёмная".equals(item) ? "moon" : "sun", 17));
            }
        }
    }

    private void installDashboardIcons() {
        visit(root, node -> {
            if (!(node instanceof VBox card) || !card.getStyleClass().contains("csa-metric-card")) return;
            for (Node child : card.getChildren()) {
                if (!(child instanceof Label label) || !label.getStyleClass().contains("csa-metric-heading")) continue;
                String kind = label.getText().contains("ФАЙЛОВ") ? "folder-tree"
                        : label.getText().contains("РИСК") ? "triangle-alert" : "bug";
                label.setGraphic(icon(kind, 16));
                label.setGraphicTextGap(7);
                return;
            }
        });
    }

    private void installFooterIcons() {
        visit(root, node -> {
            if (!(node instanceof Label label)) return;
            if (label.getStyleClass().contains("csa-footer-item")) {
                label.setGraphic(icon(label.getText().startsWith("Модель") ? "cpu" : "list-check", 15));
                label.setGraphicTextGap(7);
            } else if (label.getStyleClass().contains("csa-footer-muted")) {
                label.setGraphic(icon("info", 15));
                label.setGraphicTextGap(7);
            }
        });
    }

    /**
     * Wraps the *existing* CheckBoxTreeCell graphic rather than replacing it.
     * This retains tree-item selection and the application's status colouring.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void installTreeIcons() {
        visit(root, node -> {
            if (!(node instanceof TreeView<?> raw) || !"fileTreeView".equals(raw.getId())) return;
            TreeView<File> tree = (TreeView<File>) raw;
            Callback<TreeView<File>, TreeCell<File>> existingFactory = tree.getCellFactory();
            if (existingFactory == null) return;
            tree.setCellFactory(view -> {
                TreeCell<File> cell = existingFactory.call(view);
                cell.graphicProperty().addListener((obs, previous, current) -> decorateTreeGraphic(cell));
                cell.itemProperty().addListener((obs, previous, current) -> {
                    if (current != null) Platform.runLater(() -> decorateTreeGraphic(cell));
                });
                return cell;
            });
        });
    }

    private static void decorateTreeGraphic(TreeCell<File> cell) {
        if (Boolean.TRUE.equals(cell.getProperties().get("csa-icon-wrapping"))) return;
        if (cell.isEmpty() || cell.getItem() == null || cell.getGraphic() == null) return;
        Node current = cell.getGraphic();
        if (current instanceof HBox box && box.getStyleClass().contains("csa-tree-graphic")) {
            if (box.getChildren().size() > 1) {
                String kind = cell.getItem().isDirectory() ? "folder" : "file-code";
                Node previousIcon = box.getChildren().get(1);
                if (!kind.equals(previousIcon.getProperties().get("csa-kind"))) {
                    box.getChildren().set(1, icon(kind, 16));
                }
            }
            return;
        }
        cell.getProperties().put("csa-icon-wrapping", Boolean.TRUE);
        try {
            // Detach first, otherwise the checkbox would temporarily have two parents.
            cell.setGraphic(null);
            Node pictogram = icon(cell.getItem().isDirectory() ? "folder" : "file-code", 16);
            HBox group = new HBox(5, current, pictogram);
            group.setAlignment(Pos.CENTER_LEFT);
            group.getStyleClass().add("csa-tree-graphic");
            cell.setGraphic(group);
        } finally {
            cell.getProperties().remove("csa-icon-wrapping");
        }
    }

    private void installPlaceholders() {
        visit(root, node -> {
            if (!(node instanceof TableView<?> table)) return;
            VBox placeholder = new VBox(7);
            placeholder.setAlignment(Pos.CENTER);
            placeholder.getStyleClass().add("csa-empty-state");
            placeholder.getChildren().add(icon("shield-search", 40));
            Label title = new Label("Здесь появятся результаты проверки");
            title.getStyleClass().add("csa-placeholder-title");
            Label description = new Label("Выберите файлы и запустите анализ. Пустая таблица не означает отсутствие уязвимостей.");
            description.getStyleClass().add("csa-placeholder-description");
            description.setWrapText(true);
            description.setMaxWidth(460);
            placeholder.getChildren().addAll(title, description);
            // Delayed installation also covers skins created after the stage is shown.
            table.setPlaceholder(placeholder);
        });
    }

    private static Node icon(String kind, int size) {
        String path = PATHS.getOrDefault(kind, PATHS.get("shield-check"));
        SVGPath vector = new SVGPath();
        vector.setContent(path);
        vector.setStrokeLineCap(StrokeLineCap.ROUND);
        vector.setStrokeLineJoin(StrokeLineJoin.ROUND);
        vector.setStrokeWidth(2.1);
        vector.setFill(Color.TRANSPARENT);
        vector.getStyleClass().add("csa-vector-icon");
        vector.setMouseTransparent(true);
        double scale = size / 24.0;
        vector.setScaleX(scale);
        vector.setScaleY(scale);
        StackPane holder = new StackPane(vector);
        holder.getStyleClass().add("csa-icon-holder");
        holder.setAlignment(Pos.CENTER);
        holder.setMinSize(size + 2, size + 2);
        holder.setPrefSize(size + 2, size + 2);
        holder.setMaxSize(size + 2, size + 2);
        holder.setMouseTransparent(true);
        holder.getProperties().put("csa-kind", kind);
        return holder;
    }

    private static final Map<String, String> PATHS = Map.ofEntries(
            Map.entry("shield-check", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4"),
            Map.entry("shield-search", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M10.5 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 1 0 0-5 M12.4 13.9l1.9 1.9"),
            Map.entry("folder-open", "M3 7V5a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v2 M3 9h17l-3 11H6L3 9z"),
            Map.entry("folder", "M3 7V5a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v12H3V7z"),
            Map.entry("folder-tree", "M3 4h6v5H3V4z M15 15h6v5h-6v-5z M3 15h6v5H3v-5z M12 6h3v11 M9 17h6 M12 6h-3"),
            Map.entry("trash", "M3 6h18 M8 6V4h8v2 M5 6l1 14h12l1-14 M10 10v7 M14 10v7"),
            Map.entry("clipboard", "M9 4H7a2 2 0 0 0-2 2v14h14V6a2 2 0 0 0-2-2h-2 M9 3h6v4H9V3z M8 12h8 M8 16h8"),
            Map.entry("sparkles", "M12 3l1.5 5L18 10l-4.5 2L12 17l-1.5-5L6 10l4.5-2L12 3z M19 15l.6 1.7L21 17.3l-1.4.6L19 20l-.6-2.1-1.4-.6 1.4-.6L19 15z M5 16l.5 1.5L7 18l-1.5.5L5 20l-.5-1.5L3 18l1.5-.5L5 16z"),
            Map.entry("file-text", "M7 2h8l5 5v15H5V2h2z M15 2v6h5 M8 12h9 M8 16h9 M8 20h6"),
            Map.entry("file-input", "M14 2H6v20h14V8l-6-6z M14 2v6h6 M2 14h12 M10 10l4 4-4 4"),
            Map.entry("download", "M12 3v12 M7 10l5 5 5-5 M4 17v4h16v-4"),
            Map.entry("wrench", "M15 6a5 5 0 0 1-6 6l-6 6a2 2 0 0 0 3 3l6-6a5 5 0 0 0 6-6l-4 2-3-3 2-4a5 5 0 0 1 2 2z"),
            Map.entry("send", "M22 2L11 13 M22 2l-7 20-4-9-9-4 20-7z"),
            Map.entry("refresh", "M20 6v5h-5 M4 18v-5h5 M5 10a7 7 0 0 1 12-4l3 5 M19 14a7 7 0 0 1-12 4l-3-5"),
            Map.entry("play", "M8 5l11 7-11 7V5z"),
            Map.entry("chart", "M4 20V4 M4 20h17 M8 16l4-5 4 2 4-7"),
            Map.entry("message", "M20 15a4 4 0 0 1-4 4H9l-5 3V6a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4v9z M8 9h8 M8 13h5"),
            Map.entry("sun", "M12 8a4 4 0 1 0 0 8 4 4 0 1 0 0-8 M12 2v2 M12 20v2 M4.9 4.9l1.4 1.4 M17.7 17.7l1.4 1.4 M2 12h2 M20 12h2 M4.9 19.1l1.4-1.4 M17.7 6.3l1.4-1.4"),
            Map.entry("moon", "M20.3 15.7A9 9 0 0 1 8.3 3.7 9 9 0 1 0 20.3 15.7z"),
            Map.entry("bug", "M8 8h8v9a4 4 0 0 1-8 0V8z M9 8a3 3 0 0 1 6 0 M4 11h4 M16 11h4 M4 16h4 M16 16h4 M6 5l3 3 M18 5l-3 3"),
            Map.entry("triangle-alert", "M10.3 4.3a2 2 0 0 1 3.4 0L22 19H2L10.3 4.3z M12 9v4 M12 17h.01"),
            Map.entry("cpu", "M7 7h10v10H7V7z M10 10h4v4h-4v-4z M10 2v5 M14 2v5 M10 17v5 M14 17v5 M2 10h5 M2 14h5 M17 10h5 M17 14h5"),
            Map.entry("list-check", "M8 6h13 M8 12h13 M8 18h13 M2 6l2 2 3-4 M2 12l2 2 3-4 M2 18l2 2 3-4"),
            Map.entry("info", "M12 2a10 10 0 1 0 0 20 10 10 0 1 0 0-20 M12 10v7 M12 6h.01"),
            Map.entry("file-code", "M14 2H6v20h14V8l-6-6z M14 2v6h6 M9 13l-2 2 2 2 M15 13l2 2-2 2")
    );

    private static void visit(Node start, Consumer<Node> callback) {
        Set<Node> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        visitRecursive(start, callback, seen);
    }

    private static void visitRecursive(Node node, Consumer<Node> callback, Set<Node> seen) {
        if (node == null || !seen.add(node)) return;
        callback.accept(node);
        if (node instanceof TabPane tabs) {
            for (Tab tab : tabs.getTabs()) visitRecursive(tab.getContent(), callback, seen);
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) visitRecursive(child, callback, seen);
        }
    }
}
