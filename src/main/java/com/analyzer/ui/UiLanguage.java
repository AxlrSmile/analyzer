package com.analyzer.ui;

import javafx.beans.binding.Bindings;
import javafx.beans.binding.StringBinding;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.StringProperty;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Labeled;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextInputControl;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.function.Supplier;
import java.util.prefs.Preferences;

/** Locale for desktop presentation text. Model names, source text and report codes remain data. */
public final class UiLanguage {
    private enum Language {
        RU("ru", "Русский"), EN("en", "English"), KK("kk", "Қазақша");

        private final String code;
        private final String label;
        private final ResourceBundle messages;

        Language(String code, String label) {
            this.code = code;
            this.label = label;
            messages = code.equals("ru") ? null : ResourceBundle.getBundle(
                    "i18n.desktop", Locale.forLanguageTag(code),
                    ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES));
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final String PREFERENCE = "interface-language";
    private static final ReadOnlyObjectWrapper<Language> language = new ReadOnlyObjectWrapper<>(loadLanguage());

    private UiLanguage() {}

    private static Language loadLanguage() {
        try {
            String saved = Preferences.userNodeForPackage(UiLanguage.class).get(PREFERENCE, "ru");
            for (Language candidate : Language.values()) {
                if (candidate.code.equals(saved)) return candidate;
            }
        } catch (SecurityException ignored) {
            // Keep the default when preferences are unavailable.
        }
        return Language.RU;
    }

    private static void choose(Language selected) {
        if (selected == null) return;
        language.set(selected);
        try {
            Preferences.userNodeForPackage(UiLanguage.class).put(PREFERENCE, selected.code);
        } catch (SecurityException ignored) {
            // The selection still applies to the current window.
        }
    }

    public static String tr(String source) {
        ResourceBundle messages = language.get().messages;
        return source != null && messages != null && messages.containsKey(source)
                ? messages.getString(source) : source;
    }

    public static String format(String source, Object argument) {
        return tr(source).replace("{0}", String.valueOf(argument));
    }

    public static StringBinding localized(Supplier<String> message) {
        return Bindings.createStringBinding(message::get, language.getReadOnlyProperty());
    }

    public static ReadOnlyObjectProperty<?> languageProperty() {
        return language.getReadOnlyProperty();
    }

    public static void addChooser(HBox header) {
        Label caption = new Label();
        caption.textProperty().bind(localized(() -> tr("Язык интерфейса")));
        caption.getStyleClass().add("csa-theme-caption");
        ComboBox<Language> chooser = new ComboBox<>();
        chooser.setId("languageChooser");
        chooser.accessibleTextProperty().bind(caption.textProperty());
        caption.setLabelFor(chooser);
        chooser.getItems().setAll(Language.values());
        chooser.setValue(language.get());
        chooser.valueProperty().addListener((obs, previous, next) -> choose(next));
        header.getChildren().addAll(caption, chooser);
    }

    public static void install(Stage stage, Parent root) {
        List<Runnable> refresh = new ArrayList<>();
        track(stage.titleProperty(), refresh);
        visit(root, Collections.newSetFromMap(new IdentityHashMap<>()), refresh);
        language.addListener((obs, previous, next) -> refresh.forEach(Runnable::run));
        refresh.forEach(Runnable::run);
    }

    private static void track(StringProperty text, List<Runnable> refresh) {
        if (text.isBound()) return;
        class Translation implements Runnable {
            private String source = text.get();
            private boolean applying;

            @Override
            public void run() {
                applying = true;
                try {
                    text.set(tr(source));
                } finally {
                    applying = false;
                }
            }
        }
        var translation = new Translation();
        text.addListener((obs, previous, next) -> {
            if (translation.applying) return;
            translation.source = next;
            translation.run();
        });
        refresh.add(translation);
    }

    private static void tooltip(Tooltip tooltip, List<Runnable> refresh) {
        if (tooltip != null) track(tooltip.textProperty(), refresh);
    }

    private static void column(TableColumn<?, ?> column, List<Runnable> refresh) {
        track(column.textProperty(), refresh);
        column.getColumns().forEach(child -> column(child, refresh));
    }

    private static void visit(Node node, Set<Node> visited, List<Runnable> refresh) {
        if (node == null || !visited.add(node)) return;
        if (node instanceof Control control) tooltip(control.getTooltip(), refresh);
        if (node instanceof Labeled label) track(label.textProperty(), refresh);
        if (node instanceof TextInputControl input) track(input.promptTextProperty(), refresh);
        if (node instanceof ComboBox<?> combo) track(combo.promptTextProperty(), refresh);
        if (node instanceof TableView<?> table) {
            table.getColumns().forEach(column -> column(column, refresh));
            visit(table.getPlaceholder(), visited, refresh);
        }
        if (node instanceof TabPane tabs) {
            tabs.getTabs().forEach(tab -> {
                track(tab.textProperty(), refresh);
                tooltip(tab.getTooltip(), refresh);
                visit(tab.getContent(), visited, refresh);
            });
        }
        if (node instanceof SplitPane split) split.getItems().forEach(item -> visit(item, visited, refresh));
        if (node instanceof Parent parent) {
            parent.getChildrenUnmodifiable().forEach(child -> visit(child, visited, refresh));
        }
    }
}
