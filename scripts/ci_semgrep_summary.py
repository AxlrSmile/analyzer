#!/usr/bin/env python3
"""Validate a Semgrep JSON export and write a safe CI summary (stdlib only).

The presence of an alert is not proof of a vulnerability. The script never prints
source snippets and never silently treats a failed scan as 0 findings.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

LEVELS = {"none": None, "error": {"ERROR"}, "warning": {"ERROR", "WARNING"},
          "info": {"ERROR", "WARNING", "INFO"}}


def analyze(data: object, fail_on: str = "none") -> tuple[str, int]:
    if fail_on not in LEVELS:
        raise ValueError("fail-on must be one of: none, error, warning, info")
    if not isinstance(data, dict):
        raise ValueError("Semgrep output is not a JSON object")
    findings = data.get("results")
    errors = data.get("errors")
    paths = data.get("paths")
    if not isinstance(findings, list) or not isinstance(errors, list):
        raise ValueError("Semgrep JSON must contain results[] and errors[]")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("Semgrep JSON must contain paths.scanned[]")
    scanned = paths["scanned"]
    counts: Counter[str] = Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Malformed Semgrep finding")
        extra = finding.get("extra")
        if not isinstance(extra, dict):
            raise ValueError("Semgrep finding has no extra metadata")
        severity = str(extra.get("severity", "UNKNOWN")).upper()
        counts[severity] += 1
    md = (
        "## Semgrep CI — Java application source\n\n"
        "Scope: `src/main/java` (pilot benchmark intentionally excluded).\n\n"
        "| Metric | Count |\n| --- | ---: |\n"
        f"| Files scanned | {len(scanned)} |\n"
        f"| Findings total | {len(findings)} |\n"
        f"| ERROR | {counts['ERROR']} |\n"
        f"| WARNING | {counts['WARNING']} |\n"
        f"| INFO | {counts['INFO']} |\n"
        f"| Other severity | {sum(n for s, n in counts.items() if s not in ('ERROR', 'WARNING', 'INFO'))} |\n"
        f"| Scanner diagnostics | {len(errors)} |\n\n"
        "Semgrep findings require manual validation and are not confirmed vulnerabilities.\n"
    )
    bad_scan = bool(errors) or not scanned
    fail_levels = LEVELS[fail_on]
    policy_failed = bool(fail_levels and any(counts[s] for s in fail_levels))
    if bad_scan:
        md += "\n**Failure:** scanner errors or zero scanned files; results are incomplete.\n"
    if policy_failed:
        md += f"\n**Failure:** configured finding threshold `{fail_on}` was reached.\n"
    return md, 2 if bad_scan else 1 if policy_failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--fail-on", choices=list(LEVELS), default="none")
    args = parser.parse_args()
    try:
        data = json.loads(args.report.read_text(encoding="utf-8"))
        summary, code = analyze(data, args.fail_on)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        summary = f"## Semgrep CI\n\n**Failure:** malformed or missing scan report ({type(exc).__name__}).\n"
        print(f"Semgrep report error: {exc}")
        code = 2
    print(summary)
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a", encoding="utf-8") as output:
                output.write(summary + "\n")
        except OSError as exc:
            print(f"Could not write GitHub summary: {exc}")
            return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
