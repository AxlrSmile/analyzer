"""Tests for the CI report gate (no external dependencies)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_semgrep_summary import analyze  # noqa: E402


def report(findings=None, errors=None, scanned=None):
    return {"results": [] if findings is None else findings,
            "errors": [] if errors is None else errors,
            "paths": {"scanned": ["src/main/java/A.java"] if scanned is None else scanned}}


def issue(severity):
    return {"check_id": "java.demo", "extra": {"severity": severity}}


class SemgrepSummaryTests(unittest.TestCase):
    def test_zero_findings_is_a_success_when_files_scanned(self):
        summary, code = analyze(report())
        self.assertEqual(0, code)
        self.assertIn("Files scanned | 1", summary)

    def test_default_report_only_does_not_fail_on_findings(self):
        _, code = analyze(report(findings=[issue("ERROR")]))
        self.assertEqual(0, code)

    def test_error_gate_blocks_error_findings(self):
        summary, code = analyze(report(findings=[issue("ERROR")]), "error")
        self.assertEqual(1, code)
        self.assertIn("threshold", summary)

    def test_error_gate_allows_warning(self):
        _, code = analyze(report(findings=[issue("WARNING")]), "error")
        self.assertEqual(0, code)

    def test_warning_gate_blocks_warning(self):
        _, code = analyze(report(findings=[issue("WARNING")]), "warning")
        self.assertEqual(1, code)

    def test_scanner_error_never_counts_as_clean(self):
        _, code = analyze(report(errors=[{"message": "failure"}]))
        self.assertEqual(2, code)

    def test_zero_scanned_files_never_counts_as_clean(self):
        _, code = analyze(report(scanned=[]))
        self.assertEqual(2, code)

    def test_malformed_results_fail_closed(self):
        with self.assertRaises(ValueError):
            analyze({"results": "bad", "errors": [], "paths": {"scanned": ["A.java"]}})

    def test_untrusted_code_and_snippets_not_echoed(self):
        findings = [dict(issue("ERROR"), extra={"severity": "ERROR", "lines": "sensitive_token"})]
        summary, _ = analyze(report(findings=findings))
        self.assertNotIn("sensitive_token", summary)


if __name__ == "__main__":
    unittest.main()
