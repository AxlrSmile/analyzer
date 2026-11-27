package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class StructuredPartialFindingTest {
    private final StructuredFindingParser parser = new StructuredFindingParser(new ObjectMapper());
    private static final String VALID = """
            {"title":"SQL Injection", "severity":"HIGH", "cwe":"CWE-89",
            "startLine":2, "endLine":2,
            "evidence":"String query = input;",
            "description":"Unsanitized query", "recommendation":"Use prepared statements"}
            """;

    @Test void invalidEvidenceRetainsCandidateWithExplicitWarning() throws Exception {
        var parsed = parser.parseBestEffort("{\"vulnerabilities\":[" + VALID.replace("String query = input;", "...") + "]}");
        assertEquals(1, parsed.findings().size());
        assertEquals(1, parsed.issues().size());
        assertEquals("EVIDENCE_UNVERIFIED", parsed.findings().getFirst().getModelOutputStatus());
    }

    @Test void missingEvidenceRetainsNonConfirmedCandidate() throws Exception {
        var parsed = parser.parseBestEffort("{\"vulnerabilities\":[" + VALID.replace("\"evidence\":\"String query = input;\",", "") + "]}");
        assertEquals(1, parsed.findings().size());
        assertNull(parsed.findings().getFirst().getEvidence());
        assertEquals("EVIDENCE_UNVERIFIED", parsed.findings().getFirst().getModelOutputStatus());
    }

    @Test void badCweDoesNotDeleteOtherCandidate() throws Exception {
        var parsed = parser.parseBestEffort("{\"vulnerabilities\":["
                + VALID.replace("CWE-89", "CWE-0") + "," + VALID + "]}");
        assertEquals(2, parsed.candidateCount());
        assertEquals(1, parsed.findings().size());
        assertEquals(1, parsed.issues().size());
        assertEquals("CWE-89", parsed.findings().getFirst().getCwe());
    }

    @Test void strictParserStillRejectsMalformedEvidence() {
        assertThrows(IllegalArgumentException.class,
                () -> parser.parse("{\"vulnerabilities\":[" + VALID.replace("String query = input;", "...") + "]}"));
    }

    @Test void noCandidatesOnlyWhenOriginalArrayEmpty() throws Exception {
        var parsed = parser.parseBestEffort("{\"vulnerabilities\":[]}");
        assertTrue(parsed.findings().isEmpty());
        assertEquals(0, parsed.candidateCount());
    }

    @Test void missingArrayRejectedAsMalformedRoot() {
        assertThrows(IllegalArgumentException.class,
                () -> parser.parseBestEffort("{\"unsafe\":[]}"));
    }

    @Test void preflightCannotMatchNullOrMultilineEvidence() {
        var finding = new com.analyzer.domain.model.Vulnerability("title", "HIGH", "2", "desc", "fix");
        finding.setStartLine(2);
        finding.setEndLine(2);
        String source = "L1 | class Demo {\nL2 | String query = input;\n";
        assertFalse(StructuredEvidencePreflight.matches(source, finding));
        finding.setEvidence("String query\n= input;");
        assertFalse(StructuredEvidencePreflight.matches(source, finding));
        finding.setEvidence("String query = input;");
        assertTrue(StructuredEvidencePreflight.matches(source, finding));
        assertEquals("String query = input;", StructuredEvidencePreflight.sourceExcerpt(source, 2));
    }
}
