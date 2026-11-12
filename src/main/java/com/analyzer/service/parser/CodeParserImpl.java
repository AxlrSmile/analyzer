package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/** Splits long source files into overlapping, explicitly located source segments. */
@Service
public class CodeParserImpl implements CodeParser {
    private static final int CHUNK_ROW_SIZE = 100;
    private static final int OVERLAP_ROW_SIZE = 20;

    @Override
    public List<String> splitIntoChunks(SourceFile sourceFile) {
        return splitIntoLocatedChunks(sourceFile).stream().map(CodeChunk::prompt).toList();
    }

    @Override
    public List<CodeChunk> splitIntoLocatedChunks(SourceFile sourceFile) {
        if (sourceFile == null || sourceFile.getContent() == null
                || sourceFile.getContent().isBlank()) return List.of();

        String content = sourceFile.getContent();
        // String.lines() handles CRLF/CR/LF and does not invent an extra source
        // line at EOF when the text ends with a newline.
        List<String> lines = content.lines().toList();
        if (lines.isEmpty()) return List.of();
        if (lines.size() <= CHUNK_ROW_SIZE) {
            return List.of(new CodeChunk(content, 1, lines.size()));
        }

        List<CodeChunk> result = new ArrayList<>();
        for (int first = 0; first < lines.size(); first += CHUNK_ROW_SIZE - OVERLAP_ROW_SIZE) {
            int endExclusive = Math.min(first + CHUNK_ROW_SIZE, lines.size());
            StringBuilder prompt = new StringBuilder();
            prompt.append("// File: ").append(sourceFile.getName()).append('\n');
            prompt.append("// Language: ").append(sourceFile.getExtension()).append('\n');
            prompt.append("// Original source lines: ").append(first + 1)
                    .append('-').append(endExclusive).append('\n');
            prompt.append("// Each L-number below is an ABSOLUTE line number in the original file. ")
                    .append("Return lineRange using these L-numbers, not row positions within this excerpt.\n");
            for (int i = first; i < endExclusive; i++) {
                prompt.append('L').append(i + 1).append(" | ").append(lines.get(i)).append('\n');
            }
            result.add(new CodeChunk(prompt.toString(), first + 1, endExclusive));
            if (endExclusive == lines.size()) break;
        }
        return List.copyOf(result);
    }
}
