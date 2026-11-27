package com.analyzerweb;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WebFixComparisonTest {
    private WebFixComparison.Assessment evaluate(String original, String proposed,
            String compile, String api, String semgrep, Integer before, Integer after) {
        return WebFixComparison.assess(original, proposed, compile, api, semgrep, before, after);
    }

    @Test void noChangeIsNotAConfirmedFix() {
        assertEquals("NO_CHANGE", evaluate("class A {}", "class A {}", "PASSED", "PASSED", "COMPLETED", 1, 0).category());
    }
    @Test void failedCompilationBlocksClaim() {
        assertEquals("NOT_VALIDATED", evaluate("one", "two", "FAILED", "PASSED", "COMPLETED", 1, 0).category());
    }
    @Test void uncheckedApiRequiresManualValidation() {
        assertEquals("API_UNVERIFIED", evaluate("one", "two", "PASSED", "NOT_CHECKED", "COMPLETED", 1, 0).category());
    }
    @Test void missingStaticCheckCannotClaimImprovement() {
        assertEquals("SAST_NOT_CHECKED", evaluate("one", "two", "PASSED", "PASSED", "NOT_CHECKED", null, null).category());
    }
    @Test void increasedStaticSignalsReported() {
        assertEquals("STATIC_REGRESSION", evaluate("one", "two", "PASSED", "PASSED", "COMPLETED", 1, 2).category());
    }
    @Test void decreasedStaticSignalsNotSafetyProof() {
        var assessment = evaluate("one", "two", "PASSED", "PASSED", "COMPLETED", 1, 0);
        assertEquals("STATIC_SIGNALS_REDUCED", assessment.category());
        assertTrue(assessment.explanation().contains("не доказательство"));
    }
    @Test void unchangedStaticSignalsReported() {
        assertEquals("STATIC_SIGNALS_UNCHANGED", evaluate("one", "two", "PASSED", "PASSED", "COMPLETED", 0, 0).category());
    }
}
