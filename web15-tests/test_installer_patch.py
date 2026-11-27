"""No-file-write tests for Web 1.5's narrowly scoped Ollama prompt patch."""
from pathlib import Path
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apply_web_v15', HERE / 'apply_web_v15.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

sample = ('// Sample source\n'
          'for (int attempt = 0; attempt < 2; attempt++) {\n'
          + module.OLD_RETRY + '\n}\n').encode('utf-8')
patched = module.patch_core(sample)
assert patched != sample
assert module.patch_core(patched) == patched
assert b'WEB15_EVIDENCE_RETRY' in patched
assert b'for (int attempt = 0; attempt < 2; attempt++)' in patched
assert module.patch_core(sample.replace(b'\n', b'\r\n')).count(b'\r\n') > 1
try:
    module.patch_core(b'// unsupported source layout\n')
    raise AssertionError('Unsupported source unexpectedly accepted')
except RuntimeError:
    pass
print('Web 1.5 installer patch tests: PASS')
