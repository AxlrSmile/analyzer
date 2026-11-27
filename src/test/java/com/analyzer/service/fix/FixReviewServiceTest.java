package com.analyzer.service.fix;

import com.analyzer.service.sast.SemgrepCliService;
import com.analyzer.service.sast.SemgrepReportService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class FixReviewServiceTest {
    @TempDir Path dir;

    private FixProposal proposal() throws IOException {
        Path source = Files.writeString(dir.resolve("A.java"), "class A {}\n");
        String oldCode = Files.readString(source);
        return new FixProposal(source.toRealPath(), FixReviewService.hash(Files.readAllBytes(source)),
                oldCode, "class A { int x; }", "local-model", "manual review",
                FixReviewService.diffPreview(oldCode, "class A { int x; }"));
    }

    @Test void exportsSeparateNewFileWithoutOverwritingOriginal() throws Exception {
        var service = new FixReviewService(mock(SemgrepCliService.class));
        var proposal = proposal();
        Path output = dir.resolve("A.proposed.java");
        assertEquals(output, service.exportSeparate(proposal, output));
        assertEquals("class A { int x; }", Files.readString(output));
        assertEquals("class A {}\n", Files.readString(proposal.sourcePath()));
    }

    @Test void refusesExistingTargetAndOriginal() throws Exception {
        var service = new FixReviewService(mock(SemgrepCliService.class));
        var proposal = proposal();
        assertThrows(IOException.class, () -> service.exportSeparate(proposal, proposal.sourcePath()));
        Path existing = Files.writeString(dir.resolve("existing.java"), "do not replace");
        assertThrows(IOException.class, () -> service.exportSeparate(proposal, existing));
        assertEquals("do not replace", Files.readString(existing));
    }

    @Test void detectsChangesMadeAfterSuggestion() throws Exception {
        var service = new FixReviewService(mock(SemgrepCliService.class));
        var proposal = proposal();
        Files.writeString(proposal.sourcePath(), "class A { int changed; }");
        assertThrows(IOException.class, () -> service.exportSeparate(proposal, dir.resolve("different.java")));
        assertFalse(Files.exists(dir.resolve("different.java")));
    }

    @Test void blocksMissingAndInvalidUtf8Source() throws Exception {
        var service = new FixReviewService(mock(SemgrepCliService.class));
        var proposal = proposal();
        Files.delete(proposal.sourcePath());
        assertThrows(IOException.class, () -> service.ensureUnchanged(proposal));
        Path invalid = dir.resolve("invalid.java");
        Files.write(invalid, new byte[]{(byte)0xff, (byte)0xfe});
        assertThrows(IOException.class, () -> FixReviewService.readSource(invalid));
    }

    @Test void producesAlignedPreviewAndBoundsLargeDiff() {
        String diff = FixReviewService.diffPreview("a\nb\nc", "a\nx\nb\nc");
        assertTrue(diff.contains("+ 2: x"));
        assertFalse(diff.contains("- 2: b"));
        String huge = ("line\n").repeat(401);
        assertTrue(FixReviewService.diffPreview(huge, huge).contains("больше 400 строк"));
    }

    @Test void semgrepComparisonChecksBothVersionsWithoutModifyingSource() throws Exception {
        var proposal = proposal();
        var semgrep = mock(SemgrepCliService.class);
        var reportBefore = new SemgrepReportService.Report(List.of(
                new SemgrepReportService.Finding("rule1", "A.java", 1, 1, "ERROR", "note")), List.of());
        var reportAfter = new SemgrepReportService.Report(List.of(), List.of());
        when(semgrep.scan(any(Path.class), anyList())).thenReturn(reportBefore);
        when(semgrep.scanTemporaryCandidate(any(Path.class), anyString(), anyString())).thenReturn(reportAfter);
        var review = new FixReviewService(semgrep).recheckWithSemgrep(proposal, dir);
        assertEquals(1, review.baselineFindings());
        assertEquals(0, review.candidateFindings());
        verify(semgrep).scanTemporaryCandidate(eq(dir.toRealPath()), eq("A.java"), eq(proposal.proposedContent()));
        assertEquals("class A {}\n", Files.readString(proposal.sourcePath()));
    }

    @Test void semgrepErrorsFailClosed() throws Exception {
        var semgrep = mock(SemgrepCliService.class);
        when(semgrep.scan(any(Path.class), anyList()))
                .thenReturn(new SemgrepReportService.Report(List.of(), List.of("rule pack failed")));
        var review = new FixReviewService(semgrep);
        assertThrows(IOException.class, () -> review.recheckWithSemgrep(proposal(), dir));
        verify(semgrep, never()).scanTemporaryCandidate(any(), anyString(), anyString());
    }

    @Test void deniesParentOutsideProjectForRescan() throws Exception {
        var semgrep = mock(SemgrepCliService.class);
        var review = new FixReviewService(semgrep);
        Path wrongRoot = Files.createDirectory(dir.resolve("sub"));
        assertThrows(IOException.class, () -> review.recheckWithSemgrep(proposal(), wrongRoot));
        verifyNoInteractions(semgrep);
    }
}
