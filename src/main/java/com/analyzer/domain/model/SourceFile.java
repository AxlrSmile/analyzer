package com.analyzer.domain.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor // Оставляем для фреймворков
public class SourceFile {
    private String name;
    private String absolutePath;
    private String extension;
    private long sizeInBytes;
    private String content;
    private List<Vulnerability> vulnerabilities = new ArrayList<>(); // Инициализируется сразу

    // Явный конструктор для анализатора (без списка уязвимостей в аргументах)
    public SourceFile(String name, String absolutePath, String extension, long sizeInBytes, String content) {
        this.name = name;
        this.absolutePath = absolutePath;
        this.extension = extension;
        this.sizeInBytes = sizeInBytes;
        this.content = content;
        // vulnerabilities инициализируется как пустой ArrayList по умолчанию
    }

    // Автоматический расчет строк кода на основе содержимого
    public long getLinesOfCode() {
        if (content == null || content.isEmpty()) {
            return 0;
        }
        return content.lines().count();
    }

    // Возвращает путь файла
    public String getRelativePath() {
        return absolutePath != null ? absolutePath : name;
    }
}