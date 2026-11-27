package com.analyzer.service.scanner;

import com.analyzer.domain.model.Vulnerability;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Only removes exact repeats of WELL-LOCATED LLM findings for the same file.
 * Different descriptions, uncertain positions and SAST findings are retained.
 * This prevents losing evidence merely because titles or ranges look similar.
 */
@Service
public class FindingDeduplicationService {
    public List<Vulnerability> removeExactDuplicates(List<Vulnerability> findings) {
        if (findings == null) throw new IllegalArgumentException("Список находок равен null");
        List<Vulnerability> result = new ArrayList<>();
        Set<String> accepted = new HashSet<>();
        for (Vulnerability finding : findings) {
            if (finding == null) throw new IllegalArgumentException("Найдена null-находка");
            boolean reliable = "LOCATION_CHECKED".equals(finding.getValidationStatus())
                    && finding.hasAbsoluteLineNumbers();
            String key = canonical(finding.getTitle()) + "|" + canonical(finding.getSeverity())
                    + "|" + canonical(finding.getLineRange()) + "|"
                    + canonical(finding.getDescription());
            if (!reliable || accepted.add(key)) result.add(finding);
        }
        return List.copyOf(result);
    }

    private static String canonical(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }
}
