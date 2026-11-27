package com.analyzerweb;

import com.analyzer.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WebFindingDiagnosticsTest {
    @Test void evidenceMismatchIsSpecificButDoesNotLeakSource() {
        Vulnerability v = new Vulnerability("SQL Injection", "HIGH", "5", "", "");
        v.setValidationStatus("NEEDS_REVIEW");
        v.setModelOutputStatus("EVIDENCE_UNVERIFIED");
        v.setValidationNote("Цитата evidence не найдена на указанных строках оригинального кода: secret=top-secret");
        v.setEvidence("secret=top-secret");
        var detail = WebFindingDiagnostics.inspect(v);
        assertEquals("EVIDENCE_MISMATCH", detail.reasonCode());
        assertFalse(detail.toString().contains("top-secret"));
    }
    @Test void partialCandidatesStayUnverified() {
        Vulnerability v = new Vulnerability();
        v.setModelOutputStatus("PARTIAL_RESPONSE");
        var detail = WebFindingDiagnostics.inspect(v);
        assertEquals("PARTIAL_CANDIDATES", detail.reasonCode());
        assertTrue(detail.explanation().contains("неполный"));
    }
    @Test void citationMatchedIsNotProof() {
        Vulnerability v = new Vulnerability();
        v.setModelOutputStatus("EVIDENCE_MATCHED");
        v.setValidationStatus("LOCATION_CHECKED");
        var detail = WebFindingDiagnostics.inspect(v);
        assertEquals("CITATION_MATCHED", detail.reasonCode());
        assertTrue(detail.explanation().contains("не подтверждает"));
    }
    @Test void cweMismatchIsAdvisoryAndDoesNotRewriteModelCwe() {
        Vulnerability v = new Vulnerability("SQL Injection", "HIGH", "5", "", "");
        v.setCwe("CWE-89");
        v.setCweAdvisorStatus("SOURCE_CWE_MISMATCH");
        v.setCweSuggestion("CWE-78");
        v.setMechanismStatus("RELEVANT_PATTERN");
        var d = WebFindingDiagnostics.inspect(v);
        assertEquals("SOURCE_CWE_MISMATCH", d.cweAdvisorStatus());
        assertEquals("CWE-78", d.cweSuggestion());
        assertEquals("CWE-89", v.getCwe());
    }
    @Test void arbitraryPrivateCweNotesAndSuggestionsNeverReachApi() {
        Vulnerability v = new Vulnerability();
        v.setCweAdvisorStatus("SECRET_LOCAL_CODE");
        v.setCweSuggestion("CWE-89 + secret=password123");
        v.setCweAdvisorNote("token=PRIVATE_INFORMATION");
        var d = WebFindingDiagnostics.inspect(v);
        assertEquals("NOT_ASSESSED", d.cweAdvisorStatus());
        assertEquals("", d.cweSuggestion());
        assertFalse(d.toString().contains("PRIVATE_INFORMATION"));
    }
    @Test void sastCannotCarryLlmCweAdvice() {
        Vulnerability v = new Vulnerability();
        v.setValidationStatus("SAST_REPORTED");
        v.setCweAdvisorStatus("SOURCE_CWE_MISMATCH");
        assertEquals("NOT_APPLICABLE", WebFindingDiagnostics.inspect(v).cweAdvisorStatus());
    }
    @Test void sestRemainsSeparate() {
        Vulnerability v = new Vulnerability();
        v.setValidationStatus("SAST_REPORTED");
        assertEquals("SAST_SIGNAL", WebFindingDiagnostics.inspect(v).reasonCode());
    }
}
