package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CweConsistencyServiceTest {
    private Vulnerability finding(String title, String cwe, String evidence) {
        var v = new Vulnerability(title, "HIGH", "2", "Description", "Review");
        v.setCwe(cwe);
        v.setEvidence(evidence);
        v.setStartLine(2);
        v.setEndLine(2);
        return v;
    }

    @Test void xxeMappedToSqlCweIsFlagged() {
        var v = finding("XML External Entity (XXE) Vulnerability", "CWE-89", "DocumentBuilderFactory.newInstance()");
        CweConsistencyService.assess(v);
        assertEquals("CWE_MISMATCH", v.getSemanticStatus());
        assertTrue(v.getSemanticNote().contains("CWE-611"));
    }
    @Test void hardcodedSecretMappedToSqlCweIsFlagged() {
        var v = finding("Hardcoded Secret", "CWE-89", "API_KEY = \"demo-value\"");
        CweConsistencyService.assess(v);
        assertEquals("CWE_MISMATCH", v.getSemanticStatus());
    }
    @Test void correctSqlCategoryIsNotClaimedToBeVerified() {
        var v = finding("SQL Injection", "CWE-89", "String query = \"SELECT \" + user;");
        CweConsistencyService.assess(v);
        assertEquals("CWE_CONSISTENT", v.getSemanticStatus());
        assertTrue(v.getSemanticNote().contains("не проверка"));
    }
    @Test void sqlClaimOnUriOnlyIsFlaggedForContext() {
        var v = finding("SQL Injection", "CWE-89", "URI.create(\"https://example.invalid/\" + value)");
        CweConsistencyService.assess(v);
        assertEquals("CONTEXT_WARNING", v.getSemanticStatus());
    }
    @Test void unknownCategoryDoesNotCreateMadeUpCwe() {
        var v = finding("Review this method", "CWE-123", "public void run() {};");
        CweConsistencyService.assess(v);
        assertEquals("UNKNOWN", v.getSemanticStatus());
        assertEquals("CWE-123", v.getCwe());
    }
    @Test void knownPathTraversalCategoryIsConsistent() {
        var v = finding("Path Traversal", "CWE-22", "Path file = root.resolve(user);");
        CweConsistencyService.assess(v);
        assertEquals("CWE_CONSISTENT", v.getSemanticStatus());
    }
    @Test void readingTextIsNotEvidenceOfJavaDeserialization() {
        var v = finding("Insecure Deserialization", "CWE-502", "return Files.readString(file);");
        CweConsistencyService.assess(v);
        assertEquals("CONTEXT_WARNING", v.getSemanticStatus());
    }
    @Test void escapedHtmlIsWorthReviewing() {
        var v = finding("Cross-Site Scripting (XSS)", "CWE-79", "return Encode.forHtml(displayName);");
        CweConsistencyService.assess(v);
        assertEquals("CONTEXT_WARNING", v.getSemanticStatus());
    }
    @Test void malformedLineDoesNotEraseSemanticWarning() {
        var v = finding("XXE", "CWE-89", "DocumentBuilderFactory.newInstance()");
        new ValidatorAgent().validateLocatedChunk(new CodeChunk("class Demo {\n  DocumentBuilderFactory.newInstance();\n}", 1, 3), List.of(v));
        assertEquals("CWE_MISMATCH", v.getSemanticStatus());
        assertEquals("LOCATION_CHECKED", v.getValidationStatus());
        assertTrue(v.getValidationStatusLabel().contains("несоответствие"));
    }
    @Test void wrongEvidenceIsSeparateFromCweConsistency() {
        var v = finding("SQL Injection", "CWE-89", "String neverThere = user;");
        new ValidatorAgent().validateLocatedChunk(new CodeChunk("class Demo {\n  String sql = user;\n}", 1, 3), List.of(v));
        assertEquals("CWE_CONSISTENT", v.getSemanticStatus());
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
    }
}
