package com.analyzer.service.parser;

import com.analyzer.domain.model.SourceFile;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CodeParserImplTest {
    private final CodeParser parser = new CodeParserImpl();

    private SourceFile source(String text) {
        return new SourceFile("Long.java", Path.of("Long.java"), "Long.java", text.lines().count(), text);
    }

    @Test void shortFileRetainsOriginalPromptAndLines() {
        var chunks = parser.splitIntoLocatedChunks(source("one\r\ntwo\r\n"));
        assertEquals(1, chunks.size());
        assertEquals("one\r\ntwo\r\n", chunks.getFirst().prompt());
        assertEquals(1, chunks.getFirst().startLine());
        assertEquals(2, chunks.getFirst().endLine());
    }

    @Test void longFileHasCorrectOverlappingAbsoluteBounds() {
        var chunks = parser.splitIntoLocatedChunks(source("line\n".repeat(240)));
        assertEquals(List.of(1, 81, 161), chunks.stream().map(CodeChunk::startLine).toList());
        assertEquals(List.of(100, 180, 240), chunks.stream().map(CodeChunk::endLine).toList());
        assertTrue(chunks.get(1).prompt().contains("L81 | line"));
        assertTrue(chunks.get(1).prompt().contains("L180 | line"));
        assertFalse(chunks.get(1).prompt().contains("L181 |"));
    }

    @Test void blankFileProducesNoChunks() {
        assertTrue(parser.splitIntoLocatedChunks(source(" \n ")).isEmpty());
    }
}
