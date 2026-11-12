package com.analyzer.service.scanner;

import com.analyzer.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class FindingDeduplicationServiceTest {
    private final FindingDeduplicationService service = new FindingDeduplicationService();

    private Vulnerability item(String title, String lines, String status, boolean absolute) {
        Vulnerability finding = new Vulnerability(title, "HIGH", lines, "Same evidence", "Review");
        finding.setValidationStatus(status);
        finding.setAbsoluteLineNumbers(absolute);
        return finding;
    }

    @Test void mergesExactTrustedDuplicatesAcrossOverlappingChunks() {
        var items = service.removeExactDuplicates(List.of(
                item("Command Injection", "90", "LOCATION_CHECKED", true),
                item("  command   injection  ", "90", "LOCATION_CHECKED", true)));
        assertEquals(1, items.size());
    }

    @Test void preservesDistinctFindingsOnSameLine() {
        var items = service.removeExactDuplicates(List.of(
                item("Command Injection", "90", "LOCATION_CHECKED", true),
                item("Path Traversal", "90", "LOCATION_CHECKED", true)));
        assertEquals(2, items.size());
    }

    @Test void preservesUncertainDuplicatesForManualReview() {
        var items = service.removeExactDuplicates(List.of(
                item("Command Injection", "90", "LOCATION_INFERRED", false),
                item("Command Injection", "90", "LOCATION_INFERRED", false)));
        assertEquals(2, items.size());
    }
}
