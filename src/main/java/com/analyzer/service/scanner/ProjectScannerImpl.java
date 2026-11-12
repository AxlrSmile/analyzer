package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.agent.SecurityScannerAgent;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@Service
public class ProjectScannerImpl implements ProjectScanner {

    private final SecurityScannerAgent securityScannerAgent;

    public ProjectScannerImpl(SecurityScannerAgent securityScannerAgent) {
        this.securityScannerAgent = securityScannerAgent;
    }

    @Override
    public List<SourceFile> scanDirectory(File directory) {
        List<SourceFile> sourceFiles = new ArrayList<>();
        if (directory == null || !directory.exists() || !directory.isDirectory()) {
            return sourceFiles;
        }

        try (Stream<Path> paths = Files.walk(directory.toPath())) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> isSupportedExtension(path.toString()))
                    .forEach(path -> {
                        try {
                            String content = Files.readString(path);
                            long linesCount = Files.lines(path).count();
                            String relativePath = directory.toPath().relativize(path).toString();

                            SourceFile file = new SourceFile(
                                    path.getFileName().toString(),
                                    path,
                                    relativePath,
                                    linesCount,
                                    content
                            );
                            sourceFiles.add(file);
                        } catch (IOException e) {
                            System.err.println("Ошибка чтения файла " + path + ": " + e.getMessage());
                        }
                    });
        } catch (IOException e) {
            System.err.println("Ошибка обхода директории: " + e.getMessage());
        }

        return sourceFiles;
    }

    @Override
    public List<Vulnerability> analyzeFile(SourceFile file) {
        if (file == null || file.getContent() == null || file.getContent().isBlank()) {
            return new ArrayList<>();
        }

        // Передаем контент и имя файла для точного распознавания языка
        List<Vulnerability> vulnerabilities = securityScannerAgent.scanChunk(
                file.getContent(),
                file.getName(),
                null
        );
        file.setVulnerabilities(vulnerabilities);
        return vulnerabilities;
    }



    private boolean isSupportedExtension(String fileName) {
        String lower = fileName.toLowerCase();
        return lower.endsWith(".java") || lower.endsWith(".py") || lower.endsWith(".js")
                || lower.endsWith(".ts") || lower.endsWith(".cpp") || lower.endsWith(".cs");
    }
}