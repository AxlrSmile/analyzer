"""Non-destructive tests: exact Web 1.5 patch, idempotence, conflict rejection."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apply_web_v16', ROOT / 'apply_web_v16.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sample = ('class Demo {\nvoid x() {\n'
          + module.OLD_RETRY + '\n}\n}\n').encode('utf-8')
patched = module.patch_core(sample)
assert b'WEB16_CONTEXT_RETRY' in patched
assert b'EvidenceRetryHints.build' in patched
assert module.patch_core(patched) == patched
assert module.patch_core(sample.replace(b'\n', b'\r\n')).count(b'\r\n') > 4
for invalid in [b'unknown source', b'// WEB16_CONTEXT_RETRY\nunknown source',
                sample.replace(b'WEB15_EVIDENCE_RETRY', b'WEB15_ALTERED')]:
    try:
        module.patch_core(invalid)
        raise AssertionError('Accepted an unknown patch state')
    except RuntimeError:
        pass
for name, expected in module.PAYLOAD_HASHES.items():
    source = ROOT / 'web-v16-files' / name
    assert module.sha(source.read_bytes()) == expected
print('Web 1.6 exact-version installer tests: PASS')
