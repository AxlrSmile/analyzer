package com.analyzerweb;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Browser-only entry point. Desktop is started by CodeSecurityAnalyzerApplication as before. */
@SpringBootApplication(scanBasePackages = {
        "com.analyzer.service", "com.analyzer.config", "com.analyzerweb"
})
public class WebServerApplication {

    public static void start(String[] args) {
        locateLocalSemgrep();
        new SpringApplicationBuilder(WebServerApplication.class)
                .web(WebApplicationType.SERVLET)
                .profiles("web")
                .run(args);
    }

    private static void locateLocalSemgrep() {
        if (!System.getProperty("analyzer.semgrep.executable", "").isBlank()) return;
        Path app = Path.of("").toAbsolutePath().normalize();
        for (String candidate : List.of(
                ".venv-semgrep/Scripts/semgrep.exe",
                ".venv-semgrep/bin/semgrep")) {
            Path path = app.resolve(candidate);
            if (Files.isRegularFile(path)) {
                System.setProperty("analyzer.semgrep.executable", path.toString());
                return;
            }
        }
    }
}
