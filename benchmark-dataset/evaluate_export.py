#!/usr/bin/env python3
"""Offline evaluation of experiment exports; only explicit labels are treated as ground truth.

File metrics describe detection *alerts*, not proof of correct CWE or exploitability.
Failure files are reported as ABSTAIN, not silently treated as clean.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def fraction(n, d):
    return 0.0 if d == 0 else n / d


def file_counts(cases, findings, excluded):
    tp = fp = tn = fn = 0
    for case in cases:
        path = case['path'].replace('\\', '/')
        if path in excluded:
            continue
        predicted = bool(findings.get(path))
        positive = case['label'] == 'vulnerable'
        if positive and predicted:
            tp += 1
        elif positive:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = fraction(tp, tp + fp)
    recall = fraction(tp, tp + fn)
    f1 = fraction(2 * precision * recall, precision + recall)
    accuracy = fraction(tp + tn, tp + fp + tn + fn)
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision,
                recall=recall, f1=f1, accuracy=accuracy,
                evaluated=tp + fp + tn + fn, abstained=len(excluded))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True, help='ScanExportService JSON')
    parser.add_argument('--ground', type=Path, default=Path('benchmark-dataset/ground_truth.json'))
    parser.add_argument('--root', type=Path, default=Path('.'))
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding='utf-8'))
    ground = json.loads(args.ground.read_text(encoding='utf-8'))
    cases = ground['cases']

    paths = {c['path'].replace('\\', '/') for c in cases}
    for case in cases:
        source_path = args.root / case['path']
        if not source_path.is_file():
            parser.error(f'No source file for reproducibility: {source_path}')
        checksum = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if checksum != case['sha256']:
            parser.error(f'Ground truth source hash mismatch: {source_path}')

    files_in_export = {row['file'].replace('\\', '/') for row in report.get('files', [])}
    if paths != files_in_export:
        parser.error(f'Benchmark file coverage differs: missing={sorted(paths-files_in_export)}, '
                     f'extra={sorted(files_in_export-paths)}')
    findings = {'LLM': {}, 'SEMGREP': {}}
    for row in report['findings']:
        source = row.get('source')
        file = row['file'].replace('\\', '/')
        if source in findings and file in paths:
            findings[source].setdefault(file, []).append(row)

    coverage = report.get('coverage', {})
    diagnostics = coverage.get('diagnostics', [])
    # Version 2 exports explicit per-file states. Previous exports use diagnostics.
    if report.get('schemaVersion', 1) >= 2:
        failed = set(coverage.get('llmFailedFiles', []))
        partial = set(coverage.get('llmPartialFiles', []))
        if any(path not in paths for path in failed | partial) or failed & partial:
            parser.error('Invalid/overlapping LLM failed and partial file paths')
        if coverage.get('llmFailed', 0) != len(failed):
            parser.error('LLM failed count does not match explicit failed files')
        if coverage.get('llmPartial', 0) != len(partial):
            parser.error('LLM partial count does not match explicit partial files')
        statuses = {row['file'].replace('\\', '/'): row.get('llmStatus')
                    for row in report.get('files', [])}
        for path in paths:
            expected = 'FAILED' if path in failed else 'PARTIAL' if path in partial else 'COMPLETE'
            if statuses[path] != expected:
                parser.error(f'File status does not match coverage for {path}')
    else:
        failed_names = set()
        for diagnostic in diagnostics:
            match = re.search(r'LLM не проверила\s+([^:]+):', diagnostic)
            if match:
                failed_names.add(match.group(1).strip())
        failed = {path for path in paths if Path(path).name in failed_names}
        partial = set()
        if coverage.get('llmFailed', 0) != len(failed):
            parser.error('LLM failure count cannot be matched to unique files; do not score failures as clean')
    incomplete = failed | partial
    if not coverage.get('semgrepCompleted', False):
        parser.error('Semgrep did not complete: no complete SAST baseline')
    if coverage.get('skippedTargets', 0):
        parser.error('Skipped targets: the experiment coverage is incomplete')

    union = {path: findings['LLM'].get(path, []) + findings['SEMGREP'].get(path, []) for path in paths}
    for label, rows, excluded in [
        ('Semgrep (all files)', findings['SEMGREP'], set()),
        ('LLM (completed files only)', findings['LLM'], incomplete),
        ('LLM (conservative all files: incomplete absence counted as miss)', findings['LLM'], set()),
        ('Union (all files, Semgrep completed)', union, set()),
    ]:
        r = file_counts(cases, rows, excluded)
        print(f'{label}: TP={r["tp"]} FP={r["fp"]} TN={r["tn"]} FN={r["fn"]} '
              f'Precision={r["precision"]:.3f} Recall={r["recall"]:.3f} '
              f'F1={r["f1"]:.3f} Accuracy={r["accuracy"]:.3f} '
              f'n={r["evaluated"]} abstain={r["abstained"]}')

    targets = [c for c in cases if c['label'] == 'vulnerable' and c['path'] not in incomplete]
    cwe_hits = line_hits = both_hits = 0
    for case in targets:
        matches = findings['LLM'].get(case['path'], [])
        cwe = any(row.get('cwe') == case['cwe'] for row in matches)
        line = any(row.get('absoluteLineNumbers') is True
                   and row.get('startLine') is not None and row.get('endLine') is not None
                   and any(row['startLine'] <= target <= row['endLine']
                           for target in case['target_lines']) for row in matches)
        both = any(row.get('cwe') == case['cwe']
                   and row.get('absoluteLineNumbers') is True
                   and row.get('startLine') is not None and row.get('endLine') is not None
                   and any(row['startLine'] <= target <= row['endLine']
                           for target in case['target_lines']) for row in matches)
        cwe_hits += cwe
        line_hits += line
        both_hits += both
    print(f'CWE-aware LLM hits: {cwe_hits}/{len(targets)}; '
          f'line-aware hits: {line_hits}/{len(targets)}; '
          f'both CWE+line: {both_hits}/{len(targets)}')
    # Optional v3 advisory metric. The suggestion is not the model's output,
    # and should NEVER be added to the LLM CWE-aware numerator above.
    if report.get('schemaVersion', 1) >= 3:
        advised = sum(any(row.get('cweSuggestion') == case['cwe']
                          for row in findings['LLM'].get(case['path'], [])) for case in targets)
        advised_and_located = sum(any(
            row.get('cweSuggestion') == case['cwe']
            and row.get('absoluteLineNumbers') is True
            and row.get('startLine') is not None and row.get('endLine') is not None
            and any(row['startLine'] <= target <= row['endLine']
                    for target in case['target_lines'])
            for row in findings['LLM'].get(case['path'], [])) for case in targets)
        print(f'Separate code-based CWE advisory hits: {advised}/{len(targets)}; '
              f'advisory CWE+line: {advised_and_located}/{len(targets)}. '
              'This is NOT raw LLM classification; pilot-only, not vulnerability confirmation.')

    print(f'LLM failed files: {", ".join(sorted(failed)) or "none"}; '
          f'partial files: {", ".join(sorted(partial)) or "none"}. '
          'Partial findings remain alerts, not confirmed vulnerabilities; '
          'no semantic confirmation or exploitability is inferred from these metrics.')


if __name__ == '__main__':
    main()
