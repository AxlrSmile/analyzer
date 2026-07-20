package com.analyzer;

import javafx.application.Application;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CodeSecurityAnalyzerApplication {

    public static void main(String[] args) {
        // Вместо SpringApplication.run() передаем управление JavaFX
        Application.launch(JavaFxApplication.class, args);
    }
}