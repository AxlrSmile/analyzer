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
    @Test void sestRemainsSeparate() {
        Vulnerability v = new Vulnerability();
        v.setValidationStatus("SAST_REPORTED");
        assertEquals("SAST_SIGNAL", WebFindingDiagnostics.inspect(v).reasonCode());
    }
}
