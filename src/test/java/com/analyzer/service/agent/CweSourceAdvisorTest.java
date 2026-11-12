package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CweSourceAdvisorTest {
    private static Vulnerability advice(String source, String title, String actual) {
        return advice(source, title, actual, true);
    }

    private static Vulnerability advice(String source, String title, String actual, boolean verified) {
        var v = new Vulnerability(title, "HIGH", "1", "Review the code", "Review manually");
        v.setCwe(actual);
        v.setEvidence(source.lines().findFirst().orElse(""));
        v.setModelOutputStatus(verified ? "EVIDENCE_MATCHED" : "EVIDENCE_UNVERIFIED");
        v.setAbsoluteLineNumbers(verified);
        CweSourceAdvisor.assess(new CodeChunk(source, 1, Math.toIntExact(source.lines().count())), v);
        return v;
    }

    @Test void loggingPasswordIsNotSqlInjection() {
        var v = advice("LOG.info(\"login user=\" + user + \" password=\" + password);", "SQL Injection", "CWE-89");
        assertEquals("CWE-532", v.getCweSuggestion());
        assertEquals("SOURCE_TITLE_CONFLICT", v.getCweAdvisorStatus());
        assertEquals("CWE-89", v.getCwe());
    }

    @Test void concatenatedSqlMatchesCategoryOnly() {
        var v = advice("String q = \"SELECT id FROM accounts WHERE id='\" + name + \"'\";", "SQL Injection", "CWE-89");
        assertEquals("CATEGORY_ALIGNED", v.getCweAdvisorStatus());
        assertEquals("CWE-89", v.getCweSuggestion());
        assertTrue(v.getCweAdvisorNote().contains("не подтверждение уязвимости"));
    }

    @Test void xxeMislabeledSqlGetsProposedCategory() {
        var v = advice("DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();", "XXE Vulnerability", "CWE-89");
        assertEquals("CWE-611", v.getCweSuggestion());
        assertEquals("SOURCE_CWE_MISMATCH", v.getCweAdvisorStatus());
    }

    @Test void secretLiteralMislabeledSqlGetsProposedCategory() {
        var v = advice("private static final String API_KEY = \"DEMO_KEY_ONLY\";", "Hardcoded API Key", "CWE-89");
        assertEquals("CWE-798", v.getCweSuggestion());
        assertEquals("SOURCE_CWE_MISMATCH", v.getCweAdvisorStatus());
    }

    @Test void commandExecutionMislabeledSqlGetsProposedCategory() {
        var v = advice("return new ProcessBuilder(\"sh\", \"-c\", \"echo \" + text).start();", "Command Injection", "CWE-89");
        assertEquals("CWE-78", v.getCweSuggestion());
        assertEquals("SOURCE_CWE_MISMATCH", v.getCweAdvisorStatus());
    }

    @Test void separateProcessArgumentsDoNotProveVulnerability() {
        var v = advice("return new ProcessBuilder(\"printf\", \"%s\", text).start();", "Command Injection", "CWE-78");
        assertEquals("CATEGORY_ALIGNED", v.getCweAdvisorStatus());
        assertTrue(v.getCweAdvisorNote().contains("защитный механизм"));
    }

    @Test void getenvWithoutSqlIsNotSqlInjection() {
        var v = advice("String key = System.getenv(\"API_KEY\");", "Environment Variable Exposure", "CWE-89");
        assertNull(v.getCweSuggestion());
        assertEquals("UNSUPPORTED_SQL_CLAIM", v.getCweAdvisorStatus());
    }

    @Test void uriWithoutSqlIsNotSqlInjection() {
        var v = advice("URI endpoint = URI.create(\"https://example.invalid/a/\" + encoded);", "SQL Injection via URI", "CWE-89");
        assertNull(v.getCweSuggestion());
        assertEquals("UNSUPPORTED_SQL_CLAIM", v.getCweAdvisorStatus());
    }

    @Test void preparedStatementTriggersDefenseContextNotVulnerabilityProof() {
        var v = advice("PreparedStatement ps = c.prepareStatement(\"SELECT id FROM users WHERE id = ?\");", "SQL Injection", "CWE-89");
        assertEquals("CWE-89", v.getCweSuggestion());
        assertTrue(v.getCweAdvisorNote().contains("защитный механизм"));
    }

    @Test void canonicalizedPathTriggersDefenseNote() {
        var v = advice("Path f = realBase.resolve(requested).toRealPath();\nif (!f.startsWith(realBase)) throw new SecurityException();", "Path Traversal", "CWE-22");
        assertEquals("CWE-22", v.getCweSuggestion());
        assertTrue(v.getCweAdvisorNote().contains("защитный механизм"));
    }

    @Test void objectDeserializationGivesCorrectCategory() {
        var v = advice("return input.readObject();", "Deserialization", "CWE-78");
        assertEquals("CWE-502", v.getCweSuggestion());
        assertEquals("SOURCE_CWE_MISMATCH", v.getCweAdvisorStatus());
    }

    @Test void htmlOutputGivesXssCategoryWithoutProvingExploitability() {
        var v = advice("return \"<div>\" + displayName + \"</div>\";", "Cross-Site Scripting", "CWE-89");
        assertEquals("CWE-79", v.getCweSuggestion());
        assertEquals("SOURCE_CWE_MISMATCH", v.getCweAdvisorStatus());
    }

    @Test void noSourceSignalDoesNotInventCategory() {
        var v = advice("int size = collection.size();", "Review this method", "CWE-89");
        assertNull(v.getCweSuggestion());
        assertEquals("UNSUPPORTED_SQL_CLAIM", v.getCweAdvisorStatus());
    }

    @Test void unverifiedEvidenceIsExplicitlyProvisional() {
        var v = advice("return objectStream.readObject();", "Deserialization", "CWE-78", false);
        assertEquals("CWE-502", v.getCweSuggestion());
        assertEquals("SOURCE_HINT_UNVERIFIED_LOCATION", v.getCweAdvisorStatus());
    }

    @Test void titleOnlySuggestionDoesNotOverruleModelCwe() {
        var v = advice("String value = 42 + \"x\";", "Path Traversal", "CWE-89");
        assertNull(v.getCweSuggestion());
        assertEquals("UNSUPPORTED_SQL_CLAIM", v.getCweAdvisorStatus());
        assertEquals("CWE-89", v.getCwe());
    }

    @Test void numberedPromptHeaderIsNotSourceEvidence() {
        var v = advice("Internal document: SELECT password FROM table\nL1 | int value = 7;", "SQL Injection", "CWE-89");
        assertNull(v.getCweSuggestion());
    }
}
