package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import java.util.List;

public interface CodeParser {
    /** Legacy interface: returns prompts without location metadata. */
    List<String> splitIntoChunks(SourceFile sourceFile);

    /**
     * Location-aware interface. Multi-chunk parsers MUST override this method;
     * otherwise the original-file coordinates cannot be determined reliably.
     */
    default List<CodeChunk> splitIntoLocatedChunks(SourceFile sourceFile) {
        List<String> chunks = splitIntoChunks(sourceFile);
        if (chunks == null || chunks.isEmpty()) return List.of();
        if (chunks.size() != 1) {
            throw new IllegalStateException("Парсер не передал координаты нескольких фрагментов");
        }
        String content = sourceFile == null ? null : sourceFile.getContent();
        if (content == null || content.isBlank()) return List.of();
        // Without an override, metadata are safe only if the one prompt is
        // exactly the full source file, with no inserted header or truncation.
        if (!content.equals(chunks.getFirst())) {
            throw new IllegalStateException("Невозможно подтвердить строки фрагмента без метаданных");
        }
        return List.of(new CodeChunk(chunks.getFirst(), 1, (int) content.lines().count()));
    }
}
