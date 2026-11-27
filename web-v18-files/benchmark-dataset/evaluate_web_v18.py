#!/usr/bin/env python3
"""Evaluate one-file Web JSON exports against benchmark-dataset/ground_truth.json.
No network; read-only. Partial LLM runs are excluded from the confusion matrix,
not counted as negative/clean. Every reported result is a *file-level* alert.
"""
import argparse
import glob
import json
import re
import sys
from pathlib import Path

CASE = re.compile(r"Case\d{3}\.java$")
SOURCES = {"LLM", "Semgrep", "Union"}


def load_truth(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    truth = {}
    for item in data["cases"]:
        name = Path(item["path"]).name
        if name in truth:
            raise ValueError("duplicate ground-truth file: " + name)
        if item["label"] not in ("vulnerable", "safe"):
            raise ValueError("bad label: " + name)
        truth[name] = item["label"] == "vulnerable"
    return truth


def classify(report, origin):
    """Returns list of (basename, is_positive) or None when outcome is incomplete.
    Multi-file LLM exports lack per-file completion and are excluded to avoid
    assigning global status to individual files. Likewise don't silently create
    true negatives for missing/unmatched source files.
    """
    files = report.get("files")
    if not isinstance(files, list) or len(files) != 1 or report.get("loadedFiles") != 1:
        return None, "Expected exactly one analyzed file per JSON export"
    if origin in ("LLM", "Union"):
        if report.get("llmComplete") != 1 or report.get("llmPartial") != 0 or report.get("llmFailed") != 0:
            return None, "LLM incomplete; no clean verdict assumed"
    if origin in ("Semgrep", "Union") and report.get("sastCompleted") is not True:
        return None, "Semgrep incomplete; no clean verdict assumed"
    item = files[0]
    name = str(item.get("name", "")).replace("\\", "/").split("/")[-1]
    if not CASE.fullmatch(name):
        return None, "Unexpected file name"
    findings = item.get("findings")
    if not isinstance(findings, list):
        return None, "Missing finding list"
    is_positive = any(isinstance(f, dict) and
                      (origin == "Union" or f.get("origin") == origin) for f in findings)
    return (name, is_positive), None


def evaluate(truth, reports, origin):
    if origin not in SOURCES:
        raise ValueError("Unsupported source")
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    excluded, cases = [], set()
    accepted = 0
    for report_name, report in reports:
        example, reason = classify(report, origin)
        if reason:
            excluded.append({"report": report_name, "reason": reason})
            continue
        name, positive = example
        if name not in truth:
            excluded.append({"report": report_name, "reason": "Not in ground truth: " + name})
            continue
        cases.add(name)
        accepted += 1
        label = truth[name]
        counts[("TP" if positive else "FN") if label else ("FP" if positive else "TN")] += 1
    tp, fp, tn, fn = [counts[k] for k in ("TP", "FP", "TN", "FN")]
    ratio = lambda a, b: round(a / b, 4) if b else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision is not None and recall is not None and precision + recall else None
    return {"origin": origin, "evaluationUnit": "one complete file-level report",
            "acceptedRuns": accepted, "uniqueCases": len(cases), "totalCases": len(truth),
            "counts": counts, "precision": precision, "recall": recall, "f1": f1,
            "excluded": excluded,
            "note": "Repeated runs count separately. Incomplete scans excluded, never assumed safe. Completeness is not detection correctness."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", help="One-file exported web report JSON files")
    parser.add_argument("--truth", default="benchmark-dataset/ground_truth.json")
    parser.add_argument("--origin", choices=sorted(SOURCES), default="LLM")
    parser.add_argument("--out", help="Optional destination for JSON metrics")
    args = parser.parse_args(argv)
    try:
        truth = load_truth(args.truth)
        paths = []
        for pattern in args.reports:
            expanded = sorted(glob.glob(pattern)) if any(c in pattern for c in '*?[') else [pattern]
            paths.extend(expanded)
        paths = list(dict.fromkeys(paths))
        if not paths:
            raise ValueError('No input JSON reports matched the specified paths')
        reports = [(str(p), json.loads(Path(p).read_text(encoding="utf-8"))) for p in paths]
        result = evaluate(truth, reports, args.origin)
        body = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(body, encoding="utf-8")
        print(body, end="")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as ex:
        print("Ошибка оценки: " + str(ex), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
