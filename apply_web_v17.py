#!/usr/bin/env python3
"""Web 1.7 version-locked frontend patch for Web 1.6.
Refuses changed files, verifies payload hashes, makes timestamped backups.
Does not touch JavaFX, Ollama, user code, test data or browser localStorage.
"""
from datetime import datetime
from pathlib import Path
import hashlib
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'web-v17-files'
BASELINE_HASHES = {'src/main/resources/static/index.html': '2d0b2331da9a8d5aaf27a5d95c0ed793724fdc841c65de5f85f0c4ff33a6cb05', 'src/main/resources/static/web.js': '7e7a671d72e8213ef877a3391ea134c73c77f2d0793f4decc37c7d4ed22a2119', 'src/main/resources/static/web.css': '47ba5d86f2ebddc3a9739aa3d75e315f553a355e464166768cf5ce439bb2259e', 'src/main/resources/static/web-insights.js': 'a3f05a4d2366644433b8b6679df4b47f7b7232eddaddce71b27922416f9872cb'}
PAYLOAD_HASHES = {'src/main/resources/static/index.html': '7f1b2e44986e94b02ebdf422acd38155ecf8ae9293344b6e26395b43017d828d', 'src/main/resources/static/web.js': '789a95b014c11b6f99697af29351c3fef5f73f67b7c17552d7ec21b5b120414c', 'src/main/resources/static/web.css': '9aeae765e70a38cf9557ab1c27635bf2694dea8d94fb0b5771f47ef7f5319321', 'src/main/resources/static/web-insights.js': '0c787c3ba26d1a9abc385d6179404788f7730419bb740c668c3da6fd54fc102c', 'src/main/resources/static/web-dashboard.js': 'de1ea3e92d81c368973fb81fed03c7329c42fcbf732f53e7a1afab1e50fb07e5'}
REQUIRED_WEB16 = {
 'src/main/resources/static/web-diagnostics.js': '26e7807ea9fab66a4c0c36f229fdfba2f4b6ad0a4f921fab9cd44aba0015c8fe',
 'src/main/java/com/analyzerweb/WebFindingDiagnostics.java': '0cd912187d6e68ee14bbe7e9afe0514e1d5ccf8d139b1d4fb9db2fa22f823d96'
}

def sha(content):
    return hashlib.sha256(content).hexdigest()

def regular_file(path):
    return path.is_file() and not path.is_symlink()

def safe_parents(path):
    current = ROOT
    for part in path.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise RuntimeError('Обнаружен симлинк внутри пути: ' + str(path))

def plan():
    if not regular_file(ROOT / 'pom.xml'):
        raise RuntimeError('Распакуйте ZIP в корень code-security-analyzer рядом с pom.xml')
    for name, expected in REQUIRED_WEB16.items():
        dst = ROOT / name
        safe_parents(Path(name))
        if not regular_file(dst) or sha(dst.read_bytes()) != expected:
            raise RuntimeError('Web 1.6 не подтверждена или файл изменён: ' + name)
    result = {}
    for name, payload_sha in PAYLOAD_HASHES.items():
        rel = Path(name)
        safe_parents(rel)
        src = PAYLOAD / rel
        dst = ROOT / rel
        if not regular_file(src) or sha(src.read_bytes()) != payload_sha:
            raise RuntimeError('Повреждён или заменён файл архива: ' + name)
        if dst.exists() and not regular_file(dst):
            raise RuntimeError('Конфликт типа файла: ' + name)
        if dst.exists():
            previous = sha(dst.read_bytes())
            if previous == payload_sha:
                continue
            if previous != BASELINE_HASHES.get(name):
                raise RuntimeError('КОНФЛИКТ: локальная версия отличается от Web 1.6: ' + name)
        elif name in BASELINE_HASHES:
            raise RuntimeError('Отсутствует обязательный файл Web 1.6: ' + name)
        result[rel] = src.read_bytes()
    return result

def install():
    changes = plan()  # all conflicts checked before any writes
    if not changes:
        print('Web 1.7 уже установлен. Ничего не изменено.')
        return
    originals = {}
    backup = ROOT / 'web-v17-backup' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    for rel in changes:
        dst = ROOT / rel
        if dst.exists():
            originals[rel] = dst.read_bytes()
            safe = backup / rel
            safe.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, safe)
    written = []
    try:
        for rel, data in changes.items():
            dst = ROOT / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            temp = dst.with_name(dst.name + '.tmp-web17')
            try:
                temp.write_bytes(data)
                os.replace(temp, dst)
            finally:
                temp.unlink(missing_ok=True)
            written.append(rel)
            print('Установлено:', rel)
    except Exception:
        for rel in reversed(written):
            dst = ROOT / rel
            if rel in originals:
                dst.write_bytes(originals[rel])
            else:
                dst.unlink(missing_ok=True)
        raise
    if originals:
        print('Резервные копии изменённых файлов:', backup)
    print('Web 1.7 установлен. Выполните Maven clean test и перезапустите сервер.')

if __name__ == '__main__':
    try: install()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:', ex, file=sys.stderr)
        sys.exit(1)
