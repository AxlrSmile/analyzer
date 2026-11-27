package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StructuredEvidenceValidationTest {
    private final ValidatorAgent validator = new ValidatorAgent();

    private static Vulnerability finding(int start, int end, String evidence) {
        var result = new Vulnerability("Problem", "HIGH", start + "-" + end,
                "Candidate issue", "Review manually");
        result.setCwe("CWE-89");
        result.setStartLine(start);
        result.setEndLine(end);
        result.setEvidence(evidence);
        return result;
    }

    @Test void exactEvidenceAndLineAreLocationChecked() {
        CodeChunk chunk = new CodeChunk("class Demo {\n  String sql = value;\n}\n", 1, 3);
        var issue = finding(2, 2, "String sql = value;");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("LOCATION_CHECKED", issue.getValidationStatus());
        assertTrue(issue.hasAbsoluteLineNumbers());
    }

    @Test void fabricatedSourceLineIsNotTrusted() {
        CodeChunk chunk = new CodeChunk("class Demo {\n  String sql = value;\n}\n", 1, 3);
        var issue = finding(125, 126, "String sql = value;");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
        assertFalse(issue.hasAbsoluteLineNumbers());
    }

    @Test void wrongEvidenceOnExistingLineIsNotTrusted() {
        CodeChunk chunk = new CodeChunk("class Demo {\n  String sql = value;\n}\n", 1, 3);
        var issue = finding(2, 2, "Runtime.getRuntime().exec(user)");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
        assertFalse(issue.hasAbsoluteLineNumbers());
    }

    @Test void wrongLineForExistingEvidenceIsNotTrusted() {
        CodeChunk chunk = new CodeChunk("class Demo {\n  String sql = value;\n}\n", 1, 3);
        var issue = finding(1, 1, "String sql = value;");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
    }

    @Test void numberedLongChunkIgnoresHeaderAndChecksAbsoluteLines() {
        CodeChunk chunk = new CodeChunk("// File: Long.java\n// Original source lines: 81-82\n"
                + "L81 | class Demo {\nL82 |   String sql = value;\n", 81, 82);
        var issue = finding(82, 82, "String sql = value;");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("LOCATION_CHECKED", issue.getValidationStatus());
        assertEquals("82", issue.getLineRange());
    }

    @Test void evidenceCannotBeClaimedFromHeader() {
        CodeChunk chunk = new CodeChunk("// File: Long.java\n// security issue here\n"
                + "L81 | class Demo {\n", 81, 81);
        var issue = finding(81, 81, "security issue here");
        validator.validateLocatedChunk(chunk, List.of(issue));
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
    }
}
