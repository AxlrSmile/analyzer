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
        if (sourceFile.getPath() == null) {
            throw new IllegalArgumentException("Путь к файлу не найден!");
        }

        // Получаем абсолютный путь через объект Path
        String absolutePathStr = sourceFile.getPath().toAbsolutePath().toString();

        // Формируем путь: оригинальный абсолютный путь + .txt
        String txtPathString = absolutePathStr + ".txt";
        Path txtPath = Paths.get(txtPathString);

        // Записываем исправленный код в .txt файл
        Files.writeString(txtPath, fixedContent);

        return txtPath.getFileName().toString();
    }
}