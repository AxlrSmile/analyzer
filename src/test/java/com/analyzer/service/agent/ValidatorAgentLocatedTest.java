package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.parser.CodeChunk;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ValidatorAgentLocatedTest {
    private final ValidatorAgent agent = new ValidatorAgent();
    private final CodeChunk second = new CodeChunk("// header\nL81 | source\n", 81, 180);

    private static Vulnerability issue(String lines) {
        return new Vulnerability("Issue", "HIGH", lines, "Details", "Review");
    }

    @Test void absoluteCoordinatesDoNotCountPromptHeader() {
        Vulnerability issue = issue("L88-L93");
        agent.validateLocatedChunk(second, List.of(issue));
        assertEquals("88-93", issue.getLineRange());
        assertTrue(issue.hasAbsoluteLineNumbers());
        assertEquals("LOCATION_CHECKED", issue.getValidationStatus());
    }

    @Test void unambiguousRelativeNumberIsShiftedButNotTrusted() {
        Vulnerability issue = issue("4-7");
        agent.validateLocatedChunk(second, List.of(issue));
        assertEquals("84-87", issue.getLineRange());
        assertFalse(issue.hasAbsoluteLineNumbers());
        assertEquals("LOCATION_INFERRED", issue.getValidationStatus());
    }

    @Test void outOfBoundsAbsoluteNumberIsNotRewritten() {
        Vulnerability issue = issue("201");
        agent.validateLocatedChunk(second, List.of(issue));
        assertEquals("201", issue.getLineRange());
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
    }

    @Test void duplicateInsideChunkIsFlaggedNotDeleted() {
        var first = issue("L90");
        var secondIssue = issue("90");
        var list = agent.validateLocatedChunk(second, List.of(first, secondIssue));
        assertEquals(2, list.size());
        assertEquals("LOCATION_CHECKED", first.getValidationStatus());
        assertEquals("POSSIBLE_DUPLICATE", secondIssue.getValidationStatus());
    }

    @Test void invertedRangeStaysForManualReview() {
        Vulnerability issue = issue("95-91");
        agent.validateLocatedChunk(second, List.of(issue));
        assertEquals("NEEDS_REVIEW", issue.getValidationStatus());
    }

    @Test void absoluteAmbiguityUsesExplicitPromptContract() {
        Vulnerability issue = issue("90"); // Both 90 in excerpt and 90 as local count possible.
        agent.validateLocatedChunk(second, List.of(issue));
        assertEquals("90", issue.getLineRange()); // Model was told to return L-number.
        assertTrue(issue.hasAbsoluteLineNumbers());
    }
}
