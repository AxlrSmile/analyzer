package com.analyzer.service.fix;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FixCweReviewServiceTest {
    private final FixCweReviewService service = new FixCweReviewService();

    @Test void warnsWhenNormalizeOnlyPathCheckIsUsed() {
        var review = service.inspect("CWE-22", "Path file=base.resolve(name); "
                + "if (!file.normalize().startsWith(base)) throw new SecurityException();");
        assertEquals(FixCweReviewService.Status.REVIEW_REQUIRED, review.status());
        assertTrue(review.explanation().contains("символьные ссылки"));
    }
    @Test void realPathCheckIsOnlyARecognizedPattern() {
        var review = service.inspect("CWE-22", "Path actual=path.toRealPath(); "
                + "if (!actual.startsWith(base)) throw new SecurityException();");
        assertEquals(FixCweReviewService.Status.PATTERN_PRESENT, review.status());
        assertTrue(review.explanation().contains("TOCTOU"));
    }
    @Test void sqlParameterizedPatternFoundWithoutSecurityClaim() {
        var review = service.inspect("CWE-89", "PreparedStatement stmt=c.prepareStatement(\"SELECT * "
                + "FROM users WHERE name=?\"); stmt.setString(1, name);");
        assertEquals(FixCweReviewService.Status.PATTERN_PRESENT, review.status());
        assertTrue(review.explanation().contains("не подтверждение"));
    }
    @Test void dynamicSqlWithoutBindRequiresReview() {
        assertEquals(FixCweReviewService.Status.REVIEW_REQUIRED,
                service.inspect("CWE-89", "String q = \"SELECT * WHERE name='\"+name; stmt.execute(q);").status());
    }
    @Test void unknownCweNeverClaimsPattern() {
        assertEquals(FixCweReviewService.Status.NOT_CHECKED,
                service.inspect("CWE-338", "new java.security.SecureRandom()").status());
    }
    @Test void blankTextIsNotChecked() {
        assertEquals(FixCweReviewService.Status.NOT_CHECKED,
                service.inspect("CWE-22", "").status());
    }
}
