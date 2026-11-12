package com.analyzer.service.fix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FixExperimentServiceTest {
    @TempDir Path temp;
    private final FixCweReviewService reviewer = new FixCweReviewService();
    private final FixExperimentService service = new FixExperimentService(reviewer);

    private FixProposal proposal(String filename, String code) {
        return new FixProposal(temp.resolve(filename), "a".repeat(64), "class Baseline {}",
                code, "qwen2.5-coder:7b", "manual review", "diff");
    }
    private FixValidationService.Result valid() {
        return new FixValidationService.Result(FixValidationService.Status.PASSED,
                FixValidationService.Status.PASSED, FixValidationService.Status.PASSED, "ok");
    }
    private FixValidationService.Result invalid() {
        return new FixValidationService.Result(FixValidationService.Status.FAILED,
                FixValidationService.Status.PASSED, FixValidationService.Status.FAILED, "cannot find symbol base");
    }
    private List<FixExperimentService.Observation> outcomes(String cwe, FixExperimentService.Status... statuses) {
        List<FixExperimentService.Scenario> templates = FixExperimentService.scenariosFor(cwe);
        assertEquals(templates.size(), statuses.length);
        List<FixExperimentService.Observation> result = new ArrayList<>();
        for (int i = 0; i < statuses.length; i++) {
            result.add(new FixExperimentService.Observation(templates.get(i), statuses[i]));
        }
        return result;
    }
    private FixReviewService.Recheck scan(int original, int proposal) {
        return new FixReviewService.Recheck(original, proposal, List.of("test.sql"), List.of());
    }

    @Test void cwe22HasThreeCasesIncludingSymlink() {
        var cases = FixExperimentService.scenariosFor("CWE-22");
        assertEquals(3, cases.size());
        assertEquals("symlink", cases.get(2).id());
    }
    @Test void cwe89HasPositiveAndNegativeScenarios() {
        var cases = FixExperimentService.scenariosFor("cwe-89");
        assertEquals("normal", cases.get(0).id());
        assertEquals("injection", cases.get(1).id());
    }
    @Test void differentCwesHaveDistinctRelevantScenarios() {
        assertEquals("escape", FixExperimentService.scenariosFor("CWE-79").get(1).id());
        assertEquals("blocked", FixExperimentService.scenariosFor("CWE-918").get(1).id());
        assertEquals("external", FixExperimentService.scenariosFor("CWE-611").get(1).id());
        assertEquals("untrusted", FixExperimentService.scenariosFor("CWE-502").get(1).id());
        assertEquals("metachar", FixExperimentService.scenariosFor("CWE-78").get(1).id());
    }
    @Test void sqlCandidateWithTwoPassedExternalTestsIsOnlyPreliminaryPass() {
        var e = service.record(proposal("Case008.java", "class X { void f() { "
                        + "java.sql.PreparedStatement p = c.prepareStatement(\"SELECT id WHERE name=?\"); p.setString(1, \"x\"); "
                        + "String q = \"?\"; } }"),
                "CWE-89", valid(), scan(1, 0),
                outcomes("CWE-89", FixExperimentService.Status.PASSED, FixExperimentService.Status.PASSED),
                "External H2: 2/2 tests passed");
        assertEquals(FixExperimentService.Verdict.PRELIMINARY_PASS, e.verdict());
        assertEquals(1, service.entries().size());
        assertFalse(service.toCsv().contains("p.setString"), "Never export user source code");
    }
    @Test void skippedSymlinkMeansIncompleteEvenWhenJavaAndSastPass() {
        var e = service.record(proposal("Case002.java", "class X { void f() { String y = "
                        + "\".normalize()\"; } }"),
                "CWE-22", valid(), scan(0, 0),
                outcomes("CWE-22", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.PASSED, FixExperimentService.Status.SKIPPED),
                "Windows: symlink permission unavailable");
        assertEquals(FixExperimentService.Verdict.INCOMPLETE, e.verdict());
        assertEquals(FixCweReviewService.Status.REVIEW_REQUIRED, e.mechanism());
        assertTrue(service.toMarkdown().contains("1/0/1/0") || service.toMarkdown().contains("2/0/1/0"));
    }
    @Test void compileFailureRejects() {
        var e = service.record(proposal("Case002.java", "class Bad {}"), "CWE-22", invalid(), scan(0, 0),
                outcomes("CWE-22", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED, FixExperimentService.Status.NOT_CHECKED), "");
        assertEquals(FixExperimentService.Verdict.REJECTED, e.verdict());
    }
    @Test void failedFunctionalScenarioRejectsEvenIfSemgrepEmpty() {
        var e = service.record(proposal("Case002.java", "class Bad {}"), "CWE-22", valid(), scan(1, 0),
                outcomes("CWE-22", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.FAILED, FixExperimentService.Status.PASSED),
                "External test read outside file");
        assertEquals(FixExperimentService.Verdict.REJECTED, e.verdict());
    }
    @Test void compilerNotCheckedCannotBecomePass() {
        var e = service.record(proposal("Case008.java", "class X {}"), "CWE-89", null, scan(1, 0),
                outcomes("CWE-89", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.PASSED), "Separate tests passed");
        assertEquals(FixExperimentService.Verdict.INCOMPLETE, e.verdict());
    }
    @Test void missingSemgrepIsIncompleteEvenIfOthersPassed() {
        var e = service.record(proposal("Case008.java", "class X { void f(){"
                        + "java.sql.PreparedStatement s=null; s.setString(1, \"?\"); }}"),
                "CWE-89", valid(), null,
                outcomes("CWE-89", FixExperimentService.Status.PASSED, FixExperimentService.Status.PASSED),
                "External 2/2");
        assertEquals(FixExperimentService.Verdict.INCOMPLETE, e.verdict());
        assertEquals(FixExperimentService.Status.NOT_CHECKED, e.sast());
    }
    @Test void zeroToZeroMustNotBePreliminaryPassEvenWithAllProbesPassed() {
        var e = service.record(proposal("Case002.java", "class X { void f(){ String a="
                        + "\".toRealPath(.startsWith(\"; }}"),
                "CWE-22", valid(), scan(0, 0),
                outcomes("CWE-22", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.PASSED, FixExperimentService.Status.PASSED),
                "Reviewed isolated tests");
        assertEquals(FixExperimentService.Verdict.REVIEW_REQUIRED, e.verdict());
    }
    @Test void noImprovementRequiresReview() {
        var e = service.record(proposal("Case008.java", "prepareStatement(\"?\").setString(1, x);"),
                "CWE-89", valid(), scan(1, 1),
                outcomes("CWE-89", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.PASSED), "2 tests passed");
        assertEquals(FixExperimentService.Verdict.REVIEW_REQUIRED, e.verdict());
    }
    @Test void unknownCategoryFallbackDoesNotInventTests() {
        assertEquals("CWE-OTHER", FixExperimentService.normalizedCwe("user text"));
        assertEquals(2, FixExperimentService.scenariosFor("oops").size());
        assertEquals("negative", FixExperimentService.scenariosFor("oops").get(1).id());
    }
    @Test void forgedOrIncompleteScenarioListIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> service.record(
                proposal("X.java", "class X{}"), "CWE-22", valid(), null,
                outcomes("CWE-89", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED), ""));
    }
    @Test void manualDecisionMustHaveNotes() {
        assertThrows(IllegalArgumentException.class, () -> service.record(
                proposal("X.java", "class X{}"), "CWE-89", valid(), null,
                outcomes("CWE-89", FixExperimentService.Status.PASSED,
                        FixExperimentService.Status.NOT_CHECKED), ""));
    }
    @Test void noteFormulaInjectionNeutralizedInCsv() {
        service.record(proposal("X.java", "class X{}"), "CWE-89", null, null,
                outcomes("CWE-89", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED), "=HYPERLINK(\"evil\")");
        assertTrue(service.toCsv().contains("'=HYPERLINK"));
    }
    @Test void exportsNoAbsoluteSourcePathsOrCode() {
        service.record(proposal("X.java", "sensitive candidate body"), "CWE-OTHER", null, null,
                outcomes("CWE-OTHER", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED), "");
        assertFalse(service.toCsv().contains(temp.toString()));
        assertFalse(service.toMarkdown().contains(temp.toString()));
        assertFalse(service.toCsv().contains("sensitive candidate body"));
    }
    @Test void exportDoesNotOverwriteExistingFile() throws Exception {
        var path = Files.writeString(temp.resolve("report.csv"), "old");
        service.record(proposal("X.java", "class X{}"), "CWE-OTHER", null, null,
                outcomes("CWE-OTHER", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED), "");
        assertThrows(IOException.class, () -> service.exportCsv(path));
        assertEquals("old", Files.readString(path));
    }
    @Test void emptyJournalCannotExport() {
        assertThrows(IOException.class, () -> service.exportCsv(temp.resolve("report.csv")));
    }
    @Test void exportedCsvAndMarkdownContainRealStatuses() throws Exception {
        service.record(proposal("X.java", "class X{}"), "CWE-OTHER", null, null,
                outcomes("CWE-OTHER", FixExperimentService.Status.NOT_CHECKED,
                        FixExperimentService.Status.NOT_CHECKED), "");
        Path csv = service.exportCsv(temp.resolve("result.csv"));
        Path md = service.exportMarkdown(temp.resolve("result.md"));
        assertTrue(Files.readString(csv).contains("INCOMPLETE"));
        assertTrue(Files.readString(md).contains("Всего попыток: 1"));
    }
    @Test void repeatedAttemptsArePreservedAsSeparateObservations() {
        var prop = proposal("X.java", "class X{}");
        var obs = outcomes("CWE-OTHER", FixExperimentService.Status.NOT_CHECKED,
                FixExperimentService.Status.NOT_CHECKED);
        var first = service.record(prop, "CWE-OTHER", null, null, obs, "");
        var second = service.record(prop, "CWE-OTHER", null, null, obs, "");
        assertEquals(1L, first.number());
        assertEquals(2L, second.number());
        assertEquals(2, service.entries().size());
    }
}
