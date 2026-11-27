#!/usr/bin/env python3
"""Coarse file-level evaluation of a Semgrep JSON report (stdlib only)."""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def normalize(path):
    return str(path).replace("\\", "/").lstrip("./").lower()


def match_case(raw_path, case_path):
    p = "/" + normalize(raw_path)
    expected = "/" + normalize(case_path)
    short = "/java/" + Path(case_path).name.lower()
    return p.endswith(expected) or p.endswith(short)


def ratio(a, b):
    return a / b if b else 0.0


def run():
    parser = argparse.ArgumentParser(description="Semgrep file-level benchmark evaluation")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("ground_truth.json"))
    args = parser.parse_args()
    data = json.loads(args.report.read_text(encoding="utf-8-sig"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(data.get("results"), list):
        raise ValueError("Semgrep JSON must contain results array")
    if data.get("errors"):
        raise ValueError("Semgrep reported errors: evaluation stopped")
    cases = manifest["cases"]
    root = args.manifest.parent.parent
    for case in cases:
        source = root / case["path"]
        if not source.is_file():
            raise FileNotFoundError(f"Missing benchmark file: {source}")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest != case["sha256"]:
            raise ValueError(f"Benchmark source modified: {source}")
    scanned = (data.get("paths") or {}).get("scanned")
    if not isinstance(scanned, list):
        raise ValueError("Semgrep JSON lacks paths.scanned; coverage unknown")
    not_scanned = [case["path"] for case in cases if not any(match_case(p, case["path"]) for p in scanned)]
    if not_scanned:
        raise ValueError("Scan incomplete; files not scanned: " + ", ".join(not_scanned))
    tp = fp = tn = fn = 0
    print("Case     True         Predicted    Findings")
    print("-" * 49)
    for case in cases:
        hits = [r for r in data["results"] if match_case(r.get("path", ""), case["path"])]
        predicted = "vulnerable" if hits else "safe"
        truth = case["label"]
        if truth == "vulnerable" and hits: tp += 1
        elif truth == "vulnerable": fn += 1
        elif hits: fp += 1
        else: tn += 1
        print(f'{case["id"]:8} {truth:12} {predicted:12} {len(hits):8}')
    precision = ratio(tp, tp+fp)
    recall = ratio(tp, tp+fn)
    f1 = ratio(2*precision*recall, precision+recall)
    accuracy = ratio(tp+tn, len(cases))
    print("\nFILE-LEVEL RESULTS (coarse; see README.md)")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Precision={precision:.3f}, Recall={recall:.3f}, F1={f1:.3f}, Accuracy={accuracy:.3f}")
    print("NOTE: Any finding per file counts as positive; manual CWE/line adjudication required.")

if __name__ == "__main__":
    try:
        run()
    except Exception as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        sys.exit(2)
