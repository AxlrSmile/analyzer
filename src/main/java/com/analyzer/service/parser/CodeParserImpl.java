package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service // Регистрируем компонент в Spring
public class CodeParserImpl implements CodeParser {

    // Рекомендуемые константы для локальных моделей (Qwen2.5-Coder / DeepSeek Coder)
    private static final int CHUNK_ROW_SIZE = 100; // Размер одного чанка в строках
    private static final int OVERLAP_ROW_SIZE = 20; // Количество перекрывающихся строк

    @Override
    public List<String> splitIntoChunks(SourceFile sourceFile) {
        List<String> chunks = new ArrayList<>();
        String content = sourceFile.getContent();

        if (content == null || content.isBlank()) {
            return chunks;
        }

        // Разбиваем текст на массив строк с сохранением пустых строк
        String[] lines = content.split("\\r?\\n");

        // Если файл маленький, отправляем его целиком одним чанком
        if (lines.length <= CHUNK_ROW_SIZE) {
            chunks.add(content);
            return chunks;
        }

        int cursor = 0;
        while (cursor < lines.length) {
            // Вычисляем конечную границу текущего чанка
            int end = Math.min(cursor + CHUNK_ROW_SIZE, lines.length);

            StringBuilder chunkBuilder = new StringBuilder();

            // Заголовки-метаданные для ИИ, чтобы он понимал контекст фрагмента
            chunkBuilder.append("// File: ").append(sourceFile.getName()).append("\n");
            chunkBuilder.append("// Language: ").append(sourceFile.getExtension()).append("\n");
            chunkBuilder.append("// Lines: ").append(cursor + 1).append("-").append(end).append("\n\n");

            // Собираем строки чанка
            for (int i = cursor; i < end; i++) {
                chunkBuilder.append(lines[i]).append("\n");
            }

            chunks.add(chunkBuilder.toString());

            // Сдвигаем курсор вперед с учетом перекрытия (overlap)
            cursor += (CHUNK_ROW_SIZE - OVERLAP_ROW_SIZE);

            // Страховка от бесконечного цикла, если размеры заданы неверно
            if (end == lines.length) {
                break;
            }
        }

        return chunks;
    }
}