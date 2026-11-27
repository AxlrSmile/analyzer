import hashlib
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

release = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer18', release / 'apply_web_v18.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def baseline():
    root = Path(tempfile.mkdtemp(prefix='csa_web18_install_'))
    (root / 'pom.xml').write_text('<project/>')
    sources = {
        'src/main/resources/static/index.html': 'web-v17-files',
        'src/main/resources/static/web.js': 'web-v17-files',
        'src/main/resources/static/web.css': 'web-v17-files',
        'src/main/java/com/analyzerweb/WebFixService.java': 'web-v12-files',
        'src/main/resources/static/web-dashboard.js': 'web-v17-files',
        'src/main/resources/static/web-diagnostics.js': 'web-v16-files',
    }
    for name, directory in sources.items():
        data = (release / directory / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == (installer.BASELINE_HASHES.get(name) or installer.REQUIRED_HASHES.get(name))
        dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    shutil.copytree(release / 'web-v18-files', root / 'web-v18-files')
    shutil.copyfile(release / 'apply_web_v18.py', root / 'apply_web_v18.py')
    return root


def test_success_and_idempotent():
    root=baseline()
    try:
        old_root = installer.ROOT
        installer.ROOT=root;installer.PAYLOAD=root/'web-v18-files'
        installer.install()
        assert (root/'src/main/resources/static/web-fix-review.js').exists()
        assert any((root/'web-v18-backup').rglob('web.js'))
        assert installer.plan() == {}
        installer.install()
    finally:
        installer.ROOT=old_root;installer.PAYLOAD=release/'web-v18-files'
        shutil.rmtree(root)


def test_conflict_and_tamper():
    root=baseline()
    try:
        old_root=installer.ROOT
        installer.ROOT=root;installer.PAYLOAD=root/'web-v18-files'
        changed = root/'src/main/resources/static/web.js'
        changed.write_text(changed.read_text(encoding='utf-8')+'\n//local patch', encoding='utf-8')
        try:installer.plan();assert False, 'should reject conflict'
        except RuntimeError as e:assert 'КОНФЛИКТ' in str(e)
        # Restore and deliberately damage payload
        shutil.copyfile(release / 'web-v17-files/src/main/resources/static/web.js', changed)
        payload=root/'web-v18-files/src/main/resources/static/web.js'
        payload.write_text(payload.read_text(encoding='utf-8')+'\n//damaged payload', encoding='utf-8')
        try:installer.plan();assert False, 'should reject payload tampering'
        except RuntimeError as e:assert 'Архив' in str(e)
    finally:
        installer.ROOT=old_root;installer.PAYLOAD=release/'web-v18-files'
        shutil.rmtree(root)


if __name__=='__main__':
    test_success_and_idempotent();test_conflict_and_tamper()
    print('Web 1.8 installer: install, rerun, conflict and tamper tests passed')
