package com.analyzer;

import javafx.application.Application;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CodeSecurityAnalyzerApplication {

    public static void main(String[] args) {
        if (java.util.Arrays.asList(args).contains("--web")) {
            String[] webArgs = java.util.Arrays.stream(args)
                    .filter(arg -> !"--web".equals(arg))
                    .toArray(String[]::new);
            com.analyzerweb.WebServerApplication.start(webArgs);
            return;
        }
        Application.launch(JavaFxApplication.class, args);
    }
}