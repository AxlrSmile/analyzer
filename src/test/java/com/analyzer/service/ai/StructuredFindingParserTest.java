package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StructuredFindingParserTest {
    private final StructuredFindingParser parser = new StructuredFindingParser(new ObjectMapper());

    private static String valid() {
        return """
            {"vulnerabilities":[{"title":"SQL Injection","severity":"HIGH","cwe":"CWE-89",
              "startLine":2,"endLine":2,"evidence":"String sql = value;",
              "description":"Untrusted SQL construction","recommendation":"Use PreparedStatement"}]}
            """;
    }

    @Test void validFindingPreservesStructuredMetadata() throws Exception {
        var result = parser.parse(valid());
        assertEquals(1, result.size());
        var finding = result.getFirst();
        assertEquals("CWE-89", finding.getCwe());
        assertEquals(2, finding.getStartLine().intValue());
        assertEquals(2, finding.getEndLine().intValue());
        assertEquals("2", finding.getLineRange());
        assertEquals("String sql = value;", finding.getEvidence());
    }

    @Test void genuineEmptyResponseIsAllowed() throws Exception {
        assertTrue(parser.parse("{\"vulnerabilities\":[]}").isEmpty());
    }

    @Test void rejectsLegacyNonemptyLineRangeInsteadOfGuessing() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("""
            {"vulnerabilities":[{"title":"SQL Injection","severity":"HIGH",
             "lineRange":"L125 | L126","description":"Issue","recommendation":"Review"}]}
            """));
    }

    @Test void rejectsMissingCwe() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("\"cwe\":\"CWE-89\",", "")));
    }

    @Test void rejectsInvalidCwe() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("CWE-89", "CWE-UNKNOWN")));
    }

    @Test void rejectsStringLineNumbers() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("\"startLine\":2", "\"startLine\":\"L2\"")));
    }

    @Test void rejectsInvertedRange() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("\"endLine\":2", "\"endLine\":1")));
    }

    @Test void rejectsMissingEvidence() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("\"evidence\":\"String sql = value;\",", "")));
    }

    @Test void rejectsLongOutputInFinding() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
                valid().replace("SQL Injection", "X".repeat(170))));
    }
}
