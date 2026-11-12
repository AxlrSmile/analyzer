package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

@Service
public class FileAnalyzerImpl implements FileAnalyzer {

    private static final Map<String, String> EXTENSION_TO_LANGUAGE_MAP = new HashMap<>();

    static {
        // JVM
        EXTENSION_TO_LANGUAGE_MAP.put("java", "Java");
        EXTENSION_TO_LANGUAGE_MAP.put("kt", "Kotlin");
        EXTENSION_TO_LANGUAGE_MAP.put("scala", "Scala");

        // C / C++ (важно для DiverseVul)
        EXTENSION_TO_LANGUAGE_MAP.put("c", "C");
        EXTENSION_TO_LANGUAGE_MAP.put("h", "C/C++ Header");
        EXTENSION_TO_LANGUAGE_MAP.put("cpp", "C++");
        EXTENSION_TO_LANGUAGE_MAP.put("cc", "C++");
        EXTENSION_TO_LANGUAGE_MAP.put("cxx", "C++");
        EXTENSION_TO_LANGUAGE_MAP.put("hpp", "C++ Header");

        // Скриптовые и веб
        EXTENSION_TO_LANGUAGE_MAP.put("py", "Python");
        EXTENSION_TO_LANGUAGE_MAP.put("js", "JavaScript");
        EXTENSION_TO_LANGUAGE_MAP.put("mjs", "JavaScript");
        EXTENSION_TO_LANGUAGE_MAP.put("jsx", "JavaScript (React)");
        EXTENSION_TO_LANGUAGE_MAP.put("ts", "TypeScript");
        EXTENSION_TO_LANGUAGE_MAP.put("tsx", "TypeScript (React)");
        EXTENSION_TO_LANGUAGE_MAP.put("php", "PHP");
        EXTENSION_TO_LANGUAGE_MAP.put("rb", "Ruby");

        // Системные и бекенд
        EXTENSION_TO_LANGUAGE_MAP.put("go", "Go");
        EXTENSION_TO_LANGUAGE_MAP.put("rs", "Rust");
        EXTENSION_TO_LANGUAGE_MAP.put("cs", "C#");
        EXTENSION_TO_LANGUAGE_MAP.put("sql", "SQL");
    }

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
                file.toPath(),
                language,
                file.length(),
                content
        );
    }

    /**
     * Выделяет расширение из имени файла.
     */
    public String getFileExtension(String fileName) {
        if (fileName == null) return "";
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return "";
        }
        return fileName.substring(lastDotIndex + 1).toLowerCase();
    }

    /**
     * Проверяет, поддерживается ли расширение файла сканером.
     */
    public boolean isSupported(File file) {
        if (file == null || file.isDirectory()) return false;
        String ext = getFileExtension(file.getName());
        return EXTENSION_TO_LANGUAGE_MAP.containsKey(ext);
    }

    /**
     * Читает содержимое файла. В случае проблем с UTF-8 пробует системную кодировку
     * или Windows-1251 для старых C/C++ исходников.
     */
    private String readFileContent(File file) throws IOException {
        try {
            return Files.readString(file.toPath(), StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            try {
                return Files.readString(file.toPath(), Charset.defaultCharset());
            } catch (Exception ex) {
                // Запасной вариант для уязвимого legacy C++ кода под Windows
                return Files.readString(file.toPath(), Charset.forName("windows-1251"));
            }
        }
    }
}