package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

@Service // Регистрируем компонент в Spring
public class FileAnalyzerImpl implements FileAnalyzer {

    // Карта для преобразования расширений в читаемые названия языков для ИИ
    private static final Map<String, String> EXTENSION_TO_LANGUAGE_MAP = Map.of(
            "java", "Java",
            "py", "Python",
            "js", "JavaScript",
            "ts", "TypeScript",
            "cpp", "C++",
            "c", "C",
            "cs", "C#",
            "go", "Go",
            "php", "PHP",
            "rb", "Ruby"
    );

    @Override
    public SourceFile analyzeFile(File file) throws IOException {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("Указанный объект не является валидным файлом");
        }

        String extension = getFileExtension(file.getName());
        String language = EXTENSION_TO_LANGUAGE_MAP.getOrDefault(extension, "Unknown");

        // Безопасное чтение контента
        String content = readFileContent(file);

        return new SourceFile(
                file.getName(),
                file.getAbsolutePath(),
                language, // Записываем уже понятное имя языка вместо расширения
                file.length(),
                content
        );
    }

    /**
     * Выделяет расширение из имени файла.
     */
    private String getFileExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return "";
        }
        return fileName.substring(lastDotIndex + 1).toLowerCase();
    }

    /**
     * Читает содержимое файла. В случае проблем с UTF-8, пробует альтернативные варианты,
     * чтобы приложение не падало из-за кодировок.
     */
    private String readFileContent(File file) throws IOException {
        try {
            return Files.readString(file.toPath(), StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            // Исправлено: используем java.nio.charset.Charset.defaultCharset()
            return Files.readString(file.toPath(), java.nio.charset.Charset.defaultCharset());
        }
    }
}