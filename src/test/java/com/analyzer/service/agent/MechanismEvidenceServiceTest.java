package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MechanismEvidenceServiceTest {
    private final ValidatorAgent validator = new ValidatorAgent();

    private Vulnerability check(String code, int line, String quote, String title, String cwe) {
        var chunk = new CodeChunk(code, 1, code.lines().toList().size());
        var issue = new Vulnerability(title, "HIGH", Integer.toString(line), "Claim", "Review");
        issue.setStartLine(line);
        issue.setEndLine(line);
        issue.setEvidence(quote);
        issue.setCwe(cwe);
        validator.validateLocatedChunk(chunk, List.of(issue));
        return issue;
    }

    @Test void sqlClaimForLoggingOnlyIsFlagged() {
        var v = check("class Demo {\n  LOG.info(\"user=\" + name);\n}", 2,
                "LOG.info(\"user=\" + name);", "SQL Injection", "CWE-89");
        assertEquals("LOCATION_CHECKED", v.getValidationStatus());
        assertEquals("CWE_CONSISTENT", v.getSemanticStatus());
        assertEquals("MISSING_MECHANISM", v.getMechanismStatus());
    }

    @Test void parameterizedSqlIsFlaggedAsMitigatedContextNotAsSafeProof() {
        var v = check("class Demo {\n  PreparedStatement ps = c.prepareStatement(\"SELECT id FROM users WHERE name=?\");\n}",
                2, "PreparedStatement ps = c.prepareStatement", "SQL Injection", "CWE-89");
        assertEquals("DEFENSE_PRESENT", v.getMechanismStatus());
        assertTrue(v.getMechanismNote().contains("Проверить"));
    }

    @Test void commandApiWithoutShellIsQualified() {
        var v = check("class Demo {\n  return new ProcessBuilder(\"printf\", \"%s\", text).start();\n}",
                2, "new ProcessBuilder(\"printf\", \"%s\", text)", "Command Injection", "CWE-78");
        assertEquals("DEFENSE_PRESENT", v.getMechanismStatus());
    }

    @Test void explicitShellUseIsRelevantPatternNotConfirmedVulnerability() {
        var v = check("class Demo {\n  return new ProcessBuilder(\"sh\", \"-c\", command).start();\n}",
                2, "new ProcessBuilder(\"sh\", \"-c\", command)", "Command Injection", "CWE-78");
        assertEquals("RELEVANT_PATTERN", v.getMechanismStatus());
    }

    @Test void readingTextIsNotProofOfJavaObjectDeserialization() {
        var v = check("class Demo {\n  return Files.readString(file);\n}", 2,
                "Files.readString(file)", "Insecure Deserialization", "CWE-502");
        assertEquals("MISSING_MECHANISM", v.getMechanismStatus());
    }

    @Test void invalidEvidenceStaysUnverifiedAndDoesNotEraseOriginalFinding() {
        var v = check("class Demo {\n  LOG.info(\"done\");\n}", 2,
                "System.exit(1)", "SQL Injection", "CWE-89");
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
        assertEquals("UNVERIFIED_LOCATION", v.getMechanismStatus());
        assertEquals("SQL Injection", v.getTitle());
    }

    @Test void xxeParserWithoutRestrictionsNeedsReview() {
        var v = check("class Demo {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n}", 2,
                "DocumentBuilderFactory.newInstance()", "XXE", "CWE-611");
        assertEquals("RELEVANT_PATTERN", v.getMechanismStatus());
    }

    @Test void pathCanonicalizationIsRecordedAsMitigation() {
        var v = check("class Demo {\n  Path file = root.resolve(request).toRealPath();\n  if (!file.startsWith(root)) throw new IllegalArgumentException();\n}",
                2, "root.resolve(request).toRealPath()", "Path Traversal", "CWE-22");
        assertEquals("DEFENSE_PRESENT", v.getMechanismStatus());
    }

    @Test void hardcodedApiKeyTitleDoesNotPassAsSqlCwe() {
        var v = check("class Demo {\n  String apiKey = \"fixture\";\n}", 2,
                "String apiKey = \"fixture\";", "Hardcoded API Key", "CWE-89");
        assertEquals("CWE_MISMATCH", v.getSemanticStatus());
    }
}
