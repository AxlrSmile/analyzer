package com.analyzer.service.parser;

/**
 * A prompt containing a contiguous segment of a source file. Bounds are 1-based,
 * inclusive, and refer to the ORIGINAL file; prompt headers are not source lines.
 */
public record CodeChunk(String prompt, int startLine, int endLine) {
    public CodeChunk {
        if (prompt == null || prompt.isBlank()) {
            throw new IllegalArgumentException("Фрагмент исходного кода не может быть пустым");
        }
        if (startLine < 1 || endLine < startLine) {
            throw new IllegalArgumentException("Некорректные границы фрагмента: "
                    + startLine + "-" + endLine);
        }
    }

    public int sourceLineCount() {
        return endLine - startLine + 1;
    }
}
