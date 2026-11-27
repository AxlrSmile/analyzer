package com.analyzer.domain.model;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SourceFile {

    private String name;
    private Path path;
    private String relativePath;
    private long linesOfCode;
    private String content;
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    public SourceFile() {
    }

    // Полный конструктор
    public SourceFile(String name, Path path, String relativePath, long linesOfCode, String content) {
        this.name = name;
        this.path = path;
        this.relativePath = relativePath;
        this.linesOfCode = linesOfCode;
        this.content = content;
    }

    // Вспомогательный метод получения абсолютного пути в формате String
    public String getAbsolutePath() {
        if (path != null) {
            return path.toAbsolutePath().toString();
        }
        return relativePath != null ? relativePath : name;
    }

    public String getExtension() {
        if (name == null || !name.contains(".")) {
            return "java";
        }
        return name.substring(name.lastIndexOf('.') + 1);
    }

    // --- ГЕТТЕРЫ И СЕТТЕРЫ ---

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public Path getPath() { return path; }
    public void setPath(Path path) { this.path = path; }

    public String getRelativePath() { return relativePath; }
    public void setRelativePath(String relativePath) { this.relativePath = relativePath; }

    public long getLinesOfCode() { return linesOfCode; }
    public void setLinesOfCode(long linesOfCode) { this.linesOfCode = linesOfCode; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public List<Vulnerability> getVulnerabilities() {
        if (vulnerabilities == null) {
            vulnerabilities = new ArrayList<>();
        }
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}