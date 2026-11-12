"""Tests for non-executing v9.0 release preflight: no Java, LLM or network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'release_preflight.py'
spec = importlib.util.spec_from_file_location('release_preflight', SCRIPT)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def fixture(root):
    for name in module.REQUIRED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('placeholder', encoding='utf-8')
    (root / 'pom.xml').write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0"><properties>
<java.version>21</java.version></properties></project>''', encoding='utf-8')
    (root / '.github/workflows/devsecops-ci.yml').write_text(
        'semgrep==1.185.0\nsrc/main/java\n--config p/default\nmvnw\npull_request:\nSEMGREP_FAIL_ON\n',
        encoding='utf-8')
    (root / '.gitignore').write_text('\n'.join(module.IGNORED_MARKERS), encoding='utf-8')
    cases = []
    for n in range(1, 21):
        name = f'Case{n:03}.java'
        location = root / 'benchmark-dataset/java' / name
        location.parent.mkdir(parents=True, exist_ok=True)
        location.write_text(f'class Case{n:03} {{}}', encoding='utf-8')
        cases.append({'id': name.removesuffix('.java'),
                      'path': f'benchmark-dataset/java/{name}',
                      'label': 'safe' if n <= 10 else 'vulnerable',
                      'sha256': hashlib.sha256(location.read_bytes()).hexdigest()})
    (root / 'benchmark-dataset/ground_truth.json').write_text(
        json.dumps({'cases': cases}), encoding='utf-8')
    return cases


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cases = fixture(self.root)

    def test_required_files_pass(self):
        self.assertEqual('PASS', module.check_files(self.root).status)

    def test_required_files_missing_is_failure(self):
        (self.root / 'mvnw').unlink()
        self.assertEqual('FAIL', module.check_files(self.root).status)

    def test_java21_pass(self):
        self.assertEqual('PASS', module.check_java_version(self.root).status)

    def test_wrong_java_version_fails(self):
        p = self.root / 'pom.xml'
        p.write_text(p.read_text().replace('21', '17'), encoding='utf-8')
        self.assertEqual('FAIL', module.check_java_version(self.root).status)

    def test_dataset_20_sha256(self):
        self.assertEqual('PASS', module.check_dataset(self.root).status)

    def test_dataset_modified_source_fails(self):
        (self.root / self.cases[0]['path']).write_text('tampered', encoding='utf-8')
        self.assertIn('SHA-256 mismatch', module.check_dataset(self.root).detail)

    def test_dataset_path_traversal_fails(self):
        self.cases[0]['path'] = '../outside.java'
        (self.root / 'benchmark-dataset/ground_truth.json').write_text(
            json.dumps({'cases': self.cases}), encoding='utf-8')
        self.assertEqual('FAIL', module.check_dataset(self.root).status)

    def test_ci_workflow_passes(self):
        self.assertEqual('PASS', module.check_workflow(self.root).status)

    def test_ci_prevent_pull_request_target(self):
        p = self.root / '.github/workflows/devsecops-ci.yml'
        p.write_text(p.read_text() + '\npull_request_target:\n', encoding='utf-8')
        self.assertEqual('FAIL', module.check_workflow(self.root).status)

    def test_missing_ignore_pattern_fails(self):
        p = self.root / '.gitignore'
        p.write_text(p.read_text().replace('fix-validation/', ''), encoding='utf-8')
        self.assertEqual('FAIL', module.check_ignored(self.root).status)

    def test_no_git_is_warning_not_false_pass(self):
        self.assertEqual('WARN', module.check_tracked(self.root).status)

    def test_semgrep_findings_warning_not_automatic_fail(self):
        p = self.root / 'scan.json'
        p.write_text(json.dumps({'results': [{}, {}], 'errors': [], 'paths': {'scanned': ['A.java']}}))
        self.assertEqual('WARN', module.check_semgrep_json(p).status)

    def test_semgrep_diagnostics_fail(self):
        p = self.root / 'scan.json'
        p.write_text(json.dumps({'results': [], 'errors': [{}], 'paths': {'scanned': ['A.java']}}))
        self.assertEqual('FAIL', module.check_semgrep_json(p).status)

    def test_zero_scanned_files_fails(self):
        p = self.root / 'scan.json'
        p.write_text(json.dumps({'results': [], 'errors': [], 'paths': {'scanned': []}}))
        self.assertEqual('FAIL', module.check_semgrep_json(p).status)

    def test_report_create_new_refuses_overwrite(self):
        report = self.root / 'release-preflight-record.json'
        self.assertEqual(0, module.main(['--root', str(self.root), '--report', str(report)]))
        original = report.read_bytes()
        self.assertEqual(2, module.main(['--root', str(self.root), '--report', str(report)]))
        self.assertEqual(original, report.read_bytes())

    def test_preflight_report_records_warnings(self):
        checks = module.run_preflight(self.root)
        self.assertTrue(any(c.status == 'WARN' for c in checks))
        self.assertFalse(any(c.status == 'FAIL' for c in checks))


if __name__ == '__main__':
    unittest.main()
