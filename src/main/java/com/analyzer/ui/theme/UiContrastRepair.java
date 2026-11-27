package com.analyzer.ui.theme;

import javafx.application.Platform;
import javafx.collections.ListChangeListener;
import javafx.concurrent.Worker;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableView;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.prefs.Preferences;

/**
 * Presentation-only compatibility correction for the v1/v2/v3 JavaFX UI add-ons.
 * Fixes initial HTML backgrounds, theme switching and late TableView skin placeholders.
 * Does not alter source scanning, LLM prompts, data files or security findings.
 */
public final class UiContrastRepair {
    private final Scene scene;
    private final Parent root;
    private final List<WebView> webViews = new ArrayList<>();

    private UiContrastRepair(Stage stage, Parent root) {
        this.scene = stage.getScene();
        this.root = root;
    }

    public static void install(Stage stage, Parent root) {
        if (stage == null || stage.getScene() == null || root == null) {
            throw new IllegalArgumentException("UiContrastRepair: не найден интерфейс или Scene");
        }
        UiContrastRepair repair = new UiContrastRepair(stage, root);
        repair.install();
        // TableView's default skin may not be ready until the window has been shown.
        stage.addEventHandler(WindowEvent.WINDOW_SHOWN,
                event -> Platform.runLater(repair::refreshAll));
    }

    private void install() {
        visit(root, node -> {
            if (!(node instanceof WebView web)) return;
            webViews.add(web);
            web.getEngine().getLoadWorker().stateProperty().addListener((obs, was, now) -> {
                if (now == Worker.State.SUCCEEDED) {
                    applyWebTheme(web);
                }
            });
        });
        scene.getStylesheets().addListener((ListChangeListener<String>) change ->
                Platform.runLater(this::refreshAll));
        Platform.runLater(this::refreshAll);
    }

    private void refreshAll() {
        for (WebView web : webViews) applyWebTheme(web);
        updateCheckboxContrast();
        refreshPlaceholders();
    }

    private void updateCheckboxContrast() {
        boolean dark = isDark(scene);
        visit(root, node -> {
            if (node instanceof CheckBox cb && "selectAllCheckBox".equals(cb.getId())) {
                cb.setTextFill(Color.web(dark ? "#e8edf5" : "#223047"));
            }
        });
    }

    private void refreshPlaceholders() {
        visit(root, node -> {
            if (!(node instanceof TableView<?> table)) return;
            VBox placeholder = new VBox(8);
            placeholder.setAlignment(Pos.CENTER);
            placeholder.getStyleClass().add("csa-empty-state");
            Label title = new Label("vulnerabilitiesTable".equals(table.getId())
                    ? "Находки пока не отображаются" : "Результатов пока нет");
            title.getStyleClass().add("csa-placeholder-title");
            Label hint = new Label("vulnerabilitiesTable".equals(table.getId())
                    ? "Выберите файл и запустите анализ. Пустая таблица не доказывает безопасность."
                    : "Для отображения результатов выполните соответствующую проверку.");
            hint.getStyleClass().add("csa-placeholder-description");
            hint.setWrapText(true);
            hint.setMaxWidth(440);
            placeholder.getChildren().addAll(title, hint);
            table.setPlaceholder(placeholder);
        });
    }

    /**
     * Called by the existing MainController before loadContent. Adds CSS into
     * the HTML itself so a blank WebView isn't white when external CSS arrives late.
     */
    public static String webHtml(WebView web, String documentPrefix) {
        if (documentPrefix == null) return "";
        String block = "<style id=\"csa-v4-web-colors\">" + webCss(isDark(web == null ? null : web.getScene()))
                + "</style>";
        int headEnd = documentPrefix.indexOf("</head>");
        return headEnd < 0 ? block + documentPrefix
                : documentPrefix.substring(0, headEnd) + block + documentPrefix.substring(headEnd);
    }

    private void applyWebTheme(WebView web) {
        boolean dark = isDark(scene);
        web.setPageFill(Color.web(dark ? "#202b3d" : "#ffffff"));
        String css = webCss(dark);
        String js = "(function(){var d=document;if(!d||!d.documentElement)return;"
                + "var s=d.getElementById('csa-v4-web-colors');"
                + "if(!s){s=d.createElement('style');s.id='csa-v4-web-colors';"
                + "(d.head||d.documentElement).appendChild(s);}"
                + "s.textContent='" + escapeJs(css) + "';"
                + "d.documentElement.style.setProperty('background-color','" + (dark ? "#202b3d" : "#ffffff") + "','important');"
                + "if(d.body)d.body.style.setProperty('background-color','" + (dark ? "#202b3d" : "#ffffff") + "','important');})();";
        try {
            web.getEngine().executeScript(js);
        } catch (RuntimeException ignored) {
            // A newly loaded WebView will retry on SUCCEEDED.
        }
    }

    private static String webCss(boolean dark) {
        if (dark) return "html,body{background:#202b3d!important;color:#e8edf5!important;}"
                + "body{font-family:'Segoe UI',Arial,sans-serif!important;}"
                + "h1,h2,h3,h4,h5,h6,p,li,blockquote{color:inherit!important;}"
                + "a{color:#a4c7ff!important;}"
                + ".msg{color:#e8edf5!important;box-shadow:none!important;}"
                + ".msg.user{background:#263f60!important;border-left:4px solid #6daaff!important;}"
                + ".msg.ai{background:#28384d!important;border-left:4px solid #5ed2a0!important;}"
                + ".msg.system{background:#403a35!important;border-left:4px solid #f5b96c!important;}"
                + "pre{background:#151e2b!important;color:#dce7f8!important;}"
                + "code{background:#35465f!important;color:#dce7f8!important;}"
                + "pre code{background:transparent!important;}";
        return "html,body{background:#ffffff!important;color:#223047!important;}"
                + "body{font-family:'Segoe UI',Arial,sans-serif!important;}"
                + ".msg{color:#223047!important;}"
                + ".msg.user{background:#e3f2fd!important;}"
                + ".msg.ai{background:#ffffff!important;}"
                + ".msg.system{background:#fff3e0!important;}"
                + "pre{background:#edf1f8!important;color:#223047!important;}"
                + "code{background:#e9eef9!important;color:#223047!important;}";
    }

    private static String escapeJs(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static boolean isDark(Scene scene) {
        if (scene != null && !scene.getStylesheets().isEmpty()) {
            return scene.getStylesheets().stream().anyMatch(sheet -> sheet.contains("dark-theme.css"));
        }
        try {
            return "dark".equals(Preferences.userNodeForPackage(UiAppearanceManager.class)
                    .get("colorTheme", "light"));
        } catch (SecurityException ignored) {
            return false;
        }
    }

    private static void visit(Node start, Consumer<Node> callback) {
        Set<Node> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        visitNode(start, callback, seen);
    }

    private static void visitNode(Node node, Consumer<Node> callback, Set<Node> seen) {
        if (node == null || !seen.add(node)) return;
        callback.accept(node);
        if (node instanceof TabPane tabs) {
            for (Tab tab : tabs.getTabs()) visitNode(tab.getContent(), callback, seen);
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) visitNode(child, callback, seen);
        }
    }
}
