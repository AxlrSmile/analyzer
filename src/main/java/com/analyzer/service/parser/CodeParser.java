package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import java.util.List;

public interface CodeParser {
    /**
     * Разбивает содержимое файла на логические части (chunks) для анализа ИИ,
     * учитывая ограничения контекста.
     *
     * @param sourceFile Анализируемый файл с кодом
     * @return Список текстовых фрагментов кода
     */
    List<String> splitIntoChunks(SourceFile sourceFile);
}