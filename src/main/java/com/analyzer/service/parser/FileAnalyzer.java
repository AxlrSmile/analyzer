package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import java.io.File;
import java.io.IOException;

public interface FileAnalyzer {
    /**
     * Читает файл с диска, определяет его метаданные и возвращает заполненную модель SourceFile.
     *
     * @param file Сырой файл из сканера
     * @return Модель файла с кодом и содержимым
     * @throws IOException Если файл не удалось прочитать
     */
    SourceFile analyzeFile(File file) throws IOException;
}