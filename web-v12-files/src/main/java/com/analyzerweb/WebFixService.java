package com.analyzerweb;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.fix.FixProposal;
import com.analyzer.service.fix.FixRecommendationAgent;
import com.analyzer.service.fix.FixReviewService;
import com.analyzer.service.fix.FixValidationService;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * One-file, local-only, human-reviewed proposal. The original stays unchanged.
 * The preview can compile source via javac but NEVER runs source or a candidate.
 * Compilation is not a secure sandbox; this endpoint must not be exposed publicly.
 */
@Service
public class WebFixService {
    private final FixRecommendationAgent recommendations;
    private final FixValidationService validator;
    private final FixReviewService review;
    private final Semaphore onePreview = new Semaphore(1);

    public WebFixService(FixRecommendationAgent recommendations,
                         FixValidationService validator, FixReviewService review) {
        this.recommendations = recommendations;
        this.validator = validator;
        this.review = review;
    }

    public record FindingInput(String origin, String title, String severity, String cwe,
                               String lines, String description, String recommendation) { }
    public record PreviewRequest(String fileName, String source, String model, FindingInput finding) { }
    public record SemgrepPreview(String status, Integer before, Integer after, String details) { }
    public record PreviewResponse(String fileName, String model, String original, String proposed,
                                  String diff, String notes, String compilation, String api,
                                  String overall, String validationDetails, SemgrepPreview semgrep) { }
    public static class PreviewBusyException extends RuntimeException { }

    public PreviewResponse preview(PreviewRequest request) throws IOException {
        WebFixPolicy.Input checked = WebFixPolicy.check(request);
        if (!onePreview.tryAcquire()) throw new PreviewBusyException();
        Path dir = null;
        try {
            dir = Files.createTempDirectory("code-security-web-fix-");
            Path originalPath = dir.resolve(checked.simpleName());
            Files.writeString(originalPath, request.source(), StandardCharsets.UTF_8);
            SourceFile source = new SourceFile(checked.simpleName(), originalPath,
                    checked.simpleName(), checked.lines(), request.source());
            FindingInput input = request.finding();
            Vulnerability finding = new Vulnerability(input.title(), input.severity(),
                    input.lines(), input.description(), input.recommendation());
            finding.setCwe(input.cwe());
            finding.setValidationStatus("NEEDS_REVIEW"); // Browser metadata is untrusted.
            source.setVulnerabilities(new ArrayList<>(List.of(finding)));

            FixProposal proposal = recommendations.propose(source, request.model());
            FixValidationService.Result check = validator.validate(proposal);
            SemgrepPreview semgrep;
            if (check.compilation() != FixValidationService.Status.PASSED) {
                semgrep = new SemgrepPreview("NOT_CHECKED", null, null,
                        "Повторный Semgrep не выполнялся: компиляция предложения не подтверждена.");
            } else {
                try {
                    FixReviewService.Recheck compare = review.recheckWithSemgrep(proposal, dir);
                    semgrep = new SemgrepPreview("COMPLETED", compare.baselineFindings(),
                            compare.candidateFindings(),
                            "Количество сигналов правил. Даже 0 находок не доказывает безопасность.");
                } catch (IOException failure) {
                    semgrep = new SemgrepPreview("NOT_CHECKED", null, null,
                            "Повторный Semgrep не завершился. Проверьте его установку и серверный журнал.");
                }
            }
            return new PreviewResponse(checked.simpleName(), proposal.modelName(),
                    proposal.originalContent(), proposal.proposedContent(), proposal.diffPreview(),
                    proposal.reviewNotes(), check.compilation().name(), check.api().name(),
                    check.overall().name(), check.details(), semgrep);
        } finally {
            if (dir != null) deleteTemporary(dir);
            onePreview.release();
        }
    }

    private static void deleteTemporary(Path directory) {
        try (var paths = Files.walk(directory)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
        } catch (IOException problem) {
            System.err.println("Web Fix: не удалось полностью удалить временный каталог: "
                    + problem.getClass().getSimpleName());
        }
    }
}
