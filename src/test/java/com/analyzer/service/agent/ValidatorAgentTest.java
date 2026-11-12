package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorAgentTest {

    private final ValidatorAgent agent = new ValidatorAgent();

    private static Vulnerability finding(String range) {
        return new Vulnerability("Potential SQL injection", "HIGH", range,
                "Potential unsanitized SQL string", "Use parameterized queries");
    }

    @Test
    void validLineIsCheckedButNotConfirmed() {
        Vulnerability v = finding("L2");
        assertEquals(1, agent.validateChunk("first\nsecond\nthird", List.of(v)).size());
        assertEquals("2", v.getLineRange());
        assertEquals("LOCATION_CHECKED", v.getValidationStatus());
        assertTrue(v.getValidationNote().contains("НЕ подтверждение"));
    }

    @Test
    void nonexistentLineIsFlaggedAndNotDropped() {
        Vulnerability v = finding("99");
        assertEquals(1, agent.validateChunk("only one line", List.of(v)).size());
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
    }

    @Test
    void missingLineNeedsManualReview() {
        Vulnerability v = finding(null);
        agent.validateChunk("code", List.of(v));
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
    }

    @Test
    void reversedRangeNeedsManualReview() {
        Vulnerability v = finding("3-2");
        agent.validateChunk("a\nb\nc", List.of(v));
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
    }

    @Test
    void duplicateIsFlaggedWithoutBeingRemoved() {
        Vulnerability first = finding("1");
        Vulnerability second = finding("L1");
        List<Vulnerability> findings = agent.validateChunk("line", List.of(first, second));
        assertEquals(2, findings.size());
        assertEquals("LOCATION_CHECKED", first.getValidationStatus());
        assertEquals("POSSIBLE_DUPLICATE", second.getValidationStatus());
    }

    @Test
    void malformedRangeAndNullListFailSafely() {
        Vulnerability v = finding("line three");
        agent.validateChunk("a\nb", List.of(v));
        assertEquals("NEEDS_REVIEW", v.getValidationStatus());
        assertThrows(IllegalArgumentException.class,
                () -> agent.validateChunk("a", null));
    }
}
