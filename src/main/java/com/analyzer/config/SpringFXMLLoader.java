package com.analyzer.config;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URL;

@Component // Регистрируем наш загрузчик как компонент Spring
public class SpringFXMLLoader {

    private final ApplicationContext context;

    // Внедряем контекст Spring через конструктор (SOLID: Dependency Injection)
    public SpringFXMLLoader(ApplicationContext context) {
        this.context = context;
    }

    /**
     * Загружает FXML файл и внедряет в его контроллер зависимости из Spring.
     *
     * @param fxmlPath путь к файлу FXML относительно папки resources
     * @return корневой элемент интерфейса (Parent)
     */
    public Parent load(String fxmlPath) throws IOException {
        URL fxmlUrl = getClass().getResource(fxmlPath);
        if (fxmlUrl == null) {
            throw new IllegalArgumentException("FXML файл не найден по пути: " + fxmlPath);
        }

        FXMLLoader loader = new FXMLLoader(fxmlUrl);

        // говорим FXMLLoader использовать Spring для создания контроллеров
        loader.setControllerFactory(context::getBean);

        return loader.load();
    }
}