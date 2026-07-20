package com.analyzer;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

public class JavaFxApplication extends Application {

    private ConfigurableApplicationContext context;

    @Override
    public void init() throws Exception {
        // Запускаем контекст Spring Boot в фоновом потоке JavaFX init
        this.context = new SpringApplicationBuilder()
                .sources(CodeSecurityAnalyzerApplication.class) // Твой главный класс Spring Boot
                .run(getParameters().getRaw().toArray(new String[0]));
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Здесь мы будем инициализировать главное окно приложения, но пока оставим пустым
        primaryStage.setTitle("Локальный Анализатор Кода");
        primaryStage.setWidth(800);
        primaryStage.setHeight(600);
        primaryStage.show();
    }

    @Override
    public void stop() throws Exception {
        // Корректно закрываем Spring-контейнер при выходе из JavaFX приложения
        this.context.close();
        Platform.exit();
    }
}