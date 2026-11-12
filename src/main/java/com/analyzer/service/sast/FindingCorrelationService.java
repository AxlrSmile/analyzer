package com.analyzer.service.sast;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keeps both sources of findings. A shared line is a candidate correlation,
 * NOT independent proof that the underlying vulnerability is exploitable.
 */
@Service
public class FindingCorrelationService {
    private static final Pattern RANGE = Pattern.compile("^(\\d+)(?:-(\\d+))?$");
    private final SemgrepReportService reports;

    public record Summary(int imported, int unrelated, int overlaps) { }

    public FindingCorrelationService(SemgrepReportService reports) {
        this.reports = reports;
    }

    public Summary merge(Path projectRoot, List<SourceFile> scannedFiles,
                         SemgrepReportService.Report report) throws IOException {
        if (report == null) return new Summary(0, 0, 0);
        Map<Path, SourceFile> knownFiles = new HashMap<>();
        for (SourceFile file : scannedFiles) {
            if (file.getPath() != null) knownFiles.put(file.getPath().toRealPath(), file);
        }
        int imported = 0;
        int unrelated = 0;
        int overlaps = 0;
        for (SemgrepReportService.Finding finding : report.findings()) {
            Path absolute;
            try {
                absolute = reports.resolveInProject(projectRoot, finding.path());
            } catch (IOException ex) {
                unrelated++;
                continue;
            }
            SourceFile file = knownFiles.get(absolute);
            if (file == null) {
                unrelated++;
                continue;
            }
            // In long files we correlate ONLY locations explicitly checked
            // against original-file metadata. Legacy short-file locations can
            // be treated as absolute because they begin at source line 1.
            if (file.getContent() != null) {
                long fileLines = file.getContent().lines().count();
                for (Vulnerability candidate : file.getVulnerabilities()) {
                    if (!"LOCATION_CHECKED".equals(candidate.getValidationStatus())) continue;
                    if (fileLines > 100 && !candidate.hasAbsoluteLineNumbers()) continue;
                    Matcher m = RANGE.matcher(candidate.getLineRange() == null ? "" : candidate.getLineRange());
                    if (!m.matches()) continue;
                    long start = Long.parseLong(m.group(1));
                    long end = m.group(2) == null ? start : Long.parseLong(m.group(2));
                    if (start <= finding.endLine() && end >= finding.startLine()) {
                        candidate.setValidationStatus("POSSIBLE_SAST_MATCH");
                        candidate.setValidationNote("LLM и Semgrep указали пересекающиеся строки; правило "
                                + finding.ruleId() + ". Это только совпадение координат, "
                                + "а не подтверждённая уязвимость.");
                        overlaps++;
                    }
                }
            }
            file.getVulnerabilities().add(reports.toVulnerability(finding));
            imported++;
        }
        return new Summary(imported, unrelated, overlaps);
    }
}
