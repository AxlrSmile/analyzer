package com.analyzer.service.fix;

import com.analyzer.domain.model.SourceFile;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileFixService {

    public String saveFixedVersionAsTxt(SourceFile sourceFile, String fixedContent) throws IOException {
        if (sourceFile.getAbsolutePath() == null) {
            throw new IllegalArgumentException("Абсолютный путь к файлу не найден!");
        }

        // Формируем путь: оригинальный абсолютный путь + .txt
        // Например: /src/main/java/UserService.java -> /src/main/java/UserService.java.txt
        String txtPathString = sourceFile.getAbsolutePath() + ".txt";
        Path txtPath = Paths.get(txtPathString);

        // Записываем исправленный код в .txt файл
        Files.writeString(txtPath, fixedContent);

        return txtPath.getFileName().toString();
    }
}