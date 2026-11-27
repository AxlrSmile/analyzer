package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceRetryHintsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SOURCE = "L1 | class Demo {\n"
            + "L2 | String sql = \"SELECT id FROM users\" + name;\n"
            + "L3 | }\n";

    @Test void showsRealLineAndNeighborWithoutRewritingTheFinding() {
        String wrong = "{\"vulnerabilities\":[{\"startLine\":1,\"endLine\":1,"
                + "\"evidence\":\"made up\"}]}";
        String hint = EvidenceRetryHints.build(SOURCE, wrong, MAPPER);
        assertTrue(hint.contains("L2 | String sql ="));
        assertTrue(hint.contains("L1 | class Demo"));
        assertTrue(hint.contains("Не считай подсказку доказательством"));
    }
    @Test void invalidJsonDoesNotBreakRetry() {
        assertEquals("", EvidenceRetryHints.build(SOURCE, "broken", MAPPER));
    }
    @Test void invalidLinesDoNotGetSourceHint() {
        String bad = "{\"vulnerabilities\":[{\"startLine\":999,\"endLine\":999}]}";
        assertEquals("", EvidenceRetryHints.build(SOURCE, bad, MAPPER));
    }
    @Test void boundsPromptAndSkipsLongSourceLines() {
        String huge = "x".repeat(1000);
        String source = "L1 | " + huge + "\nL2 | safe();\n";
        String reply = "{\"vulnerabilities\":[{\"startLine\":1,\"endLine\":2}]}";
        String hint = EvidenceRetryHints.build(source, reply, MAPPER);
        assertTrue(hint.length() < 2000);
        assertFalse(hint.contains(huge));
        assertTrue(hint.contains("L2 | safe();"));
    }
}
