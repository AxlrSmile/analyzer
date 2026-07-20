package com.analyzer.service.scanner;

import java.io.File;
import java.io.IOException;
import java.util.List;

public interface ProjectScanner {
    /**
     * Сканирует указанную директорию и возвращает список файлов с исходным кодом.
     *
     * @param projectDir Корневая папка проекта
     * @return Список текстовых файлов, содержащих код
     * @throws IOException Если возникли проблемы при доступе к файловой системе
     */
    List<File> scanDirectory(File projectDir) throws IOException;
}