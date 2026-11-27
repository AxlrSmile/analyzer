package com.analyzer;

import com.analyzer.config.SpringFXMLLoader;
import com.analyzer.ui.theme.UiDashboardEnhancer;
import com.analyzer.ui.theme.UiIconPolish;
import com.analyzer.ui.theme.UiContrastRepair;
import com.analyzer.ui.theme.UiPolishV5;
import com.analyzer.ui.theme.UiAppearanceManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

public class JavaFxApplication extends Application {

    private ConfigurableApplicationContext context;

    @Override
    public void init() throws Exception {
        this.context = new SpringApplicationBuilder()
                .sources(CodeSecurityAnalyzerApplication.class)
                .web(org.springframework.boot.WebApplicationType.NONE)
                .run(getParameters().getRaw().toArray(new String[0]));
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Достаем наш кастомный загрузчик из контекста Spring
        SpringFXMLLoader fxmlLoader = context.getBean(SpringFXMLLoader.class);

        // Загружаем интерфейс главного окна
        Parent root = fxmlLoader.load("/fxml/main-view.fxml");

        primaryStage.setTitle("Локальный Анализатор Кода");
        primaryStage.setScene(new Scene(root));
        UiAppearanceManager.install(primaryStage, root);
        UiDashboardEnhancer.install(primaryStage, root);
        UiIconPolish.install(primaryStage, root);
        UiContrastRepair.install(primaryStage, root);
        UiPolishV5.install(primaryStage, root);
        primaryStage.show();
    }

    @Override
    public void stop() throws Exception {
        this.context.close();
        Platform.exit();
    }
}