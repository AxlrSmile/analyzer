#!/usr/bin/env python3
"""Code Security Analyzer 9.0: non-executing, deterministic release preflight.

This script NEVER executes user-submitted Java, a generated fix, Maven, or Semgrep.
It checks repository metadata and optionally summarizes an already produced Semgrep JSON.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

REQUIRED_FILES = (
    'pom.xml', 'mvnw.cmd', 'mvnw', '.gitignore',
    '.github/workflows/devsecops-ci.yml',
    'src/main/java/com/analyzer/CodeSecurityAnalyzerApplication.java',
    'src/main/java/com/analyzer/JavaFxApplication.java',
    'src/main/java/com/analyzer/service/sast/SemgrepCliService.java',
    'src/main/java/com/analyzer/service/fix/FixRecommendationAgent.java',
    'src/main/java/com/analyzer/service/fix/FixValidationService.java',
    'src/main/java/com/analyzer/service/fix/FixExperimentService.java',
    'scripts/ci_semgrep_summary.py',
    'scripts/plot_fix_experiments.py',
    'benchmark-dataset/ground_truth.json',
)
IGNORED_MARKERS = (
    '.venv-', 'fix-validation/', '*.proposed.java', '*.sarif',
    '*-security-findings.json', '.env', 'fix-experiments-*.csv',
    'release-preflight-*.json',
)
BAD_TRACKED = (
    re.compile(r'(^|/)\.env($|\.)'),
    re.compile(r'(^|/)\.venv[^/]*/'),
    re.compile(r'(^|/)fix-validation/'),
    re.compile(r'(^|/)fix-experiments-.*\.(csv|md|svg)$'),
    re.compile(r'(^|/)release-preflight-.*\.json$'),
    re.compile(r'(^|/)pip-.*\.whl$'),
    re.compile(r'(^|/).*\.proposed\.java$'),
    re.compile(r'(^|/).*security-findings\.json$'),
    re.compile(r'(^|/)ci-reports/'),
    re.compile(r'(^|/)\.idea/'),
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # PASS, WARN, FAIL
    detail: str


def check_files(root: Path) -> Check:
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        return Check('Required project files', 'FAIL', 'Missing: ' + ', '.join(missing))
    return Check('Required project files', 'PASS', f'All {len(REQUIRED_FILES)} required files found')


def check_java_version(root: Path) -> Check:
    try:
        tree = ET.parse(root / 'pom.xml')
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        version = tree.findtext('.//m:properties/m:java.version', namespaces=ns)
        if version is None:
            version = tree.findtext('.//properties/java.version')
        if version != '21':
            return Check('Java version', 'FAIL', f'Expected JDK 21 in pom.xml, found {version!r}')
        return Check('Java version', 'PASS', 'pom.xml declares JDK 21')
    except (OSError, ET.ParseError) as exc:
        return Check('Java version', 'FAIL', f'Cannot read pom.xml: {type(exc).__name__}')


def check_dataset(root: Path) -> Check:
    try:
        d = json.loads((root / 'benchmark-dataset/ground_truth.json').read_text(encoding='utf-8'))
        cases = d['cases']
        if not isinstance(cases, list) or len(cases) != 20:
            return Check('Benchmark integrity', 'FAIL', 'Expected exactly 20 benchmark entries')
        ids = set()
        labels = {'safe': 0, 'vulnerable': 0}
        for case in cases:
            cid = case['id']
            label = case['label']
            if cid in ids or label not in labels:
                return Check('Benchmark integrity', 'FAIL', 'Duplicate ID or unknown label')
            ids.add(cid)
            labels[label] += 1
            name = case['path']
            source = (root / name).resolve()
            if not source.is_relative_to(root.resolve()) or not source.is_file():
                return Check('Benchmark integrity', 'FAIL', f'Missing or out-of-tree benchmark: {cid}')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if digest != case.get('sha256'):
                return Check('Benchmark integrity', 'FAIL', f'SHA-256 mismatch: {cid}')
        if labels != {'safe': 10, 'vulnerable': 10}:
            return Check('Benchmark integrity', 'FAIL', f'Wrong label distribution: {labels}')
        return Check('Benchmark integrity', 'PASS', '20 cases: 10 safe, 10 vulnerable; SHA-256 verified')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return Check('Benchmark integrity', 'FAIL', f'Invalid ground truth: {type(exc).__name__}')


def check_workflow(root: Path) -> Check:
    try:
        workflow = (root / '.github/workflows/devsecops-ci.yml').read_text(encoding='utf-8')
    except OSError:
        return Check('CI design', 'FAIL', 'CI workflow not found')
    required = ('semgrep==1.185.0', 'src/main/java', '--config p/default',
                'mvnw', 'pull_request:', 'SEMGREP_FAIL_ON')
    missing = [token for token in required if token not in workflow]
    if missing or 'pull_request_target:' in workflow:
        return Check('CI design', 'FAIL', 'Missing CI guards: ' + ', '.join(missing)
                     + ('; pull_request_target is not allowed' if 'pull_request_target:' in workflow else ''))
    return Check('CI design', 'PASS', 'JDK tests, pinned Semgrep, source-only scope and report gate configured')


def check_ignored(root: Path) -> Check:
    try:
        data = (root / '.gitignore').read_text(encoding='utf-8')
    except OSError:
        return Check('Generated outputs ignored', 'FAIL', '.gitignore unavailable')
    missing = [item for item in IGNORED_MARKERS if item not in data]
    if missing:
        return Check('Generated outputs ignored', 'FAIL', 'Missing ignore patterns: ' + ', '.join(missing))
    return Check('Generated outputs ignored', 'PASS', 'Local reports, virtual envs, fixes and preflight JSON ignored')


def check_tracked(root: Path) -> Check:
    if not (root / '.git').exists():
        return Check('Tracked local artifacts', 'WARN', 'No .git metadata; check again in the Git checkout')
    try:
        proc = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=10, check=True)
        entries = [p.decode('utf-8', errors='replace').replace('\\', '/')
                   for p in proc.stdout.split(b'\0') if p]
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return Check('Tracked local artifacts', 'WARN', 'Cannot inspect tracked Git paths')
    risky = [p for p in entries if p != '.env.example'
             and any(rule.search(p) for rule in BAD_TRACKED)]
    if risky:
        return Check('Tracked local artifacts', 'FAIL',
                     f'{len(risky)} generated or sensitive-looking paths are tracked; inspect git ls-files')
    return Check('Tracked local artifacts', 'PASS', f'Checked {len(entries)} Git-tracked paths')


def check_semgrep_json(path: Path) -> Check:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('results'), list) \
                or not isinstance(data.get('errors'), list):
            raise ValueError('Missing Semgrep results/errors arrays')
        errors, hits = data['errors'], data['results']
        scanned = data.get('paths', {}).get('scanned', [])
        if errors:
            return Check('Semgrep report', 'FAIL', f'{len(errors)} scanner diagnostics; not a clean scan')
        if not isinstance(scanned, list) or not scanned:
            return Check('Semgrep report', 'FAIL', 'No scanned files recorded')
        if hits:
            return Check('Semgrep report', 'WARN',
                         f'{len(hits)} findings on {len(scanned)} scanned files; manual triage required')
        return Check('Semgrep report', 'PASS',
                     f'No rule matches on {len(scanned)} scanned files; not proof of safety')
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return Check('Semgrep report', 'FAIL', f'Invalid Semgrep report: {type(exc).__name__}')


def run_preflight(root: Path, semgrep_json: Path | None = None) -> list[Check]:
    checks = [check_files(root), check_java_version(root), check_dataset(root),
              check_workflow(root), check_ignored(root), check_tracked(root)]
    if semgrep_json is not None:
        checks.append(check_semgrep_json(semgrep_json))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Non-executing Code Security Analyzer 9.0 release preflight')
    parser.add_argument('--root', type=Path, default=Path('.'), help='Project root')
    parser.add_argument('--semgrep-json', type=Path, help='Optional existing Semgrep JSON (not an LLM export)')
    parser.add_argument('--report', type=Path, help='Write a new JSON audit record (never overwrite)')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    checks = run_preflight(root, args.semgrep_json)
    for check in checks:
        print(f'[{check.status:4}] {check.name}: {check.detail}')
    failures = sum(check.status == 'FAIL' for check in checks)
    warnings = sum(check.status == 'WARN' for check in checks)
    print(f'Summary: {failures} FAIL, {warnings} WARN. Preflight does not execute Java, Maven or Semgrep.')
    if args.report is not None:
        record = {
            'schemaVersion': 1,
            'generatedAtUtc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'purpose': 'Release readiness metadata, not a security certification',
            'checks': [asdict(item) for item in checks],
            'failures': failures,
            'warnings': warnings,
        }
        try:
            with args.report.open('x', encoding='utf-8', newline='\n') as output:
                json.dump(record, output, indent=2, ensure_ascii=False)
                output.write('\n')
        except FileExistsError:
            print('ERROR: report already exists; choose a new filename', file=sys.stderr)
            return 2
        except OSError as exc:
            print(f'ERROR: could not save report ({type(exc).__name__})', file=sys.stderr)
            return 2
        print(f'Saved preflight report: {args.report}')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
