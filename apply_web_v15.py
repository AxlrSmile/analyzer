#!/usr/bin/env python3
"""Web 1.5 safe install onto the exact Web 1.4 frontend and Web 1.1 scan service.
No network, no execution of uploaded projects, no change to JavaFX."""
from datetime import datetime
from pathlib import Path
import hashlib
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'web-v15-files'
WEB = Path('src/main/resources/static')
BACKEND = Path('src/main/java/com/analyzerweb')
OLLAMA = Path('src/main/java/com/analyzer/service/ai/OllamaClient.java')

# Exact hashes of verified Web 1.4 files, from the previous release archive.
OLD_HASHES = {
    str(WEB / 'index.html'): 'c64aae1b88b6863174c307d6731d4b6ea280be5e268dc4ff4817f6913ee96af4',
    str(WEB / 'web.css'): 'fa37aaac95350606b9a123c890550769f5734b392d3b50a967c0291e7edee484',
    str(WEB / 'web.js'): '263ba07c002829621111f554ebd4eba65f618eaf44e3bcaa9fe8c743dd5ce9d8',
    str(WEB / 'web-insights.js'): '3904a2176b476a7ef001c8ad680fc9465ad223dd1c6577ae1cb7a56ea44027d8',
    str(BACKEND / 'WebScanService.java'): None,  # filled from reference source SHA-256 below
}
OLD_HASHES[str(BACKEND / 'WebScanService.java')] = '3b884e8ab57ae2b170fb9775a1d3598dda605c7bca2c69e185528c0870c94e85'


# Checksums of the release payload. Unknown or corrupted files are not installed.
PAYLOAD_HASHES = {'src/main/java/com/analyzerweb/WebFindingDiagnostics.java': '915c37013cbbc548311e174aa766e344c592394350e6c2181eabca888ccf5b75', 'src/main/java/com/analyzerweb/WebScanService.java': '89c669332f0a49f9f7a3c41950c315c2a3851fac08e1f74683af5e39dbadb84b', 'src/main/resources/static/index.html': '9c3067dd8dc0af3daaf7b9082db2b70305cdb5abaf57c7279fa55758dd8c47e2', 'src/main/resources/static/web-diagnostics.js': '74e8061e149affc23e07d888c261ee7d8303c19ee91d6caf0ee62bd4cea8555a', 'src/main/resources/static/web-insights.js': '0d190802f972513b72cfad21222a293684382abc843b347c8fb910f17438e998', 'src/main/resources/static/web.css': '7bd2ab18f911b2ad875f7c9f67a059db8d6bd48d65c4f19406193c1d172032ac', 'src/main/resources/static/web.js': 'f6df6aad578b3f4482750ace80cc859689961a764d79b7069ce68c77addce5b4', 'src/test/java/com/analyzerweb/WebFindingDiagnosticsTest.java': 'db2862f8b8f22d2e65e862aa2833b7fe36ed02d7c79e6c363673e689244fa41f'}

# Source is versioned in GitHub separately from web files. Only a single,
# exact, short retry-instruction block is modified. Refuse any unknown layout.
OLD_RETRY = '''            String currentPrompt = attempt == 0 ? prompt : prompt + "\\n\\n"
                    + "ПОВТОРНЫЙ ЗАПРОС: предыдущий ответ не прошёл проверку: "
                    + lastValidationFailure + ". Исправь формат, координаты и evidence. "
                    + "Цитируй РОВНО ОДНУ реальную строку с правильным L-номером. "
                    + "Сохрани обоснованные находки, не заменяй их пустым списком. Верни только JSON.";'''
NEW_RETRY = '''            // WEB15_EVIDENCE_RETRY: targeted guidance; still only two attempts.
            boolean evidenceProblem = lastValidationFailure.contains("evidence")
                    || lastValidationFailure.contains("цитат");
            String retryAdvice = evidenceProblem
                    ? "ЦИТАТА: открой исходный блок с L-номерами; возьми точную непрерывную "
                    + "однострочную подстроку из указанного L-номера. Не пиши Lномер | в evidence, "
                    + "не сокращай код, не добавляй многоточия и не выдумывай строки. "
                    : "СТРУКТУРА: проверь обязательные поля, целые номера строк и корректный CWE. ";
            String currentPrompt = attempt == 0 ? prompt : prompt + "\\n\\n"
                    + "ПОВТОРНЫЙ ЗАПРОС: предыдущий ответ не прошёл проверку: "
                    + lastValidationFailure + ". " + retryAdvice
                    + "Все startLine/endLine — абсолютные номера исходных L-строк. "
                    + "Сохрани обоснованные находки, не заменяй их пустым списком. Верни только JSON.";'''


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def patch_core(raw: bytes) -> bytes:
    try:
        value = raw.decode('utf-8')
    except UnicodeDecodeError as e:
        raise RuntimeError('OllamaClient.java не является UTF-8') from e
    was_crlf = '\r\n' in value
    normalized = value.replace('\r\n', '\n')
    if 'WEB15_EVIDENCE_RETRY' in normalized:
        if normalized.count('WEB15_EVIDENCE_RETRY') != 1 or NEW_RETRY not in normalized:
            raise RuntimeError('Конфликт: OllamaClient.java уже содержит другой патч Web 1.5')
        return raw
    if normalized.count(OLD_RETRY) != 1 or normalized.count('for (int attempt = 0; attempt < 2; attempt++)') != 1:
        raise RuntimeError('Конфликт: в OllamaClient.java изменён блок повтора Ollama; ничего не перезаписано')
    result = normalized.replace(OLD_RETRY, NEW_RETRY)
    if was_crlf:
        result = result.replace('\n', '\r\n')
    return result.encode('utf-8')


def deploy():
    if not (ROOT / 'pom.xml').is_file():
        raise RuntimeError('Распакуйте ZIP в корень code-security-analyzer рядом с pom.xml')
    required = [WEB / 'web-insights.js', WEB / 'web-journal.js', OLLAMA,
                BACKEND / 'WebFixController.java']
    for rel in required:
        if not (ROOT / rel).is_file():
            raise RuntimeError('Отсутствует компонент Web 1.4: ' + str(rel))
    paths = [WEB / 'index.html', WEB / 'web.css', WEB / 'web.js',
             WEB / 'web-diagnostics.js', WEB / 'web-insights.js', BACKEND / 'WebScanService.java',
             BACKEND / 'WebFindingDiagnostics.java',
             Path('src/test/java/com/analyzerweb/WebFindingDiagnosticsTest.java')]
    planned = {}
    for rel in paths:
        src = PAYLOAD / rel
        dest = ROOT / rel
        if not src.is_file():
            raise RuntimeError('В архиве отсутствует: ' + str(rel))
        if dest.is_symlink():
            raise RuntimeError('Символическая ссылка вместо файла: ' + str(rel))
        if dest.exists() and not dest.is_file():
            raise RuntimeError('Путь является каталогом: ' + str(rel))
        new = src.read_bytes()
        expected_payload = PAYLOAD_HASHES.get(rel.as_posix())
        if expected_payload is None or sha(new) != expected_payload:
            raise RuntimeError('Повреждён или изменён файл обновления: ' + str(rel))
        if dest.exists():
            old = dest.read_bytes()
            if old == new: continue
            expected = OLD_HASHES.get(str(rel))
            if expected is None:
                raise RuntimeError('КОНФЛИКТ: существующий файл Web 1.5 уже изменён: ' + str(rel))
            if sha(old) != expected:
                raise RuntimeError('КОНФЛИКТ: локально изменён файл ' + str(rel) + '; ничего не перезаписано')
        elif str(rel) in OLD_HASHES:
            raise RuntimeError('Отсутствует обязательный файл Web 1.4: ' + str(rel))
        planned[rel] = new
    core_path = ROOT / OLLAMA
    if core_path.is_symlink():
        raise RuntimeError('Ссылка вместо OllamaClient.java')
    core_old = core_path.read_bytes()
    core_new = patch_core(core_old)
    if core_old != core_new:
        planned[OLLAMA] = core_new
    if not planned:
        print('Web 1.5 уже установлен. Повторных изменений нет.');return
    backup = ROOT / 'web-v15-backup' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    originals = {}
    for rel in planned:
        dest = ROOT / rel
        if dest.exists():
            originals[rel] = dest.read_bytes()
            dst_backup = backup / rel
            dst_backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dest, dst_backup)
    changed = []
    try:
        for rel, new in planned.items():
            dest = ROOT / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            temp = dest.with_name(dest.name + '.tmp-web15')
            try:
                temp.write_bytes(new)
                os.replace(temp, dest)
            finally:
                temp.unlink(missing_ok=True)
            changed.append(rel)
            print('Установлено:', rel)
    except Exception:
        for rel in reversed(changed):
            dest = ROOT / rel
            if rel in originals:
                dest.write_bytes(originals[rel])
            else:
                dest.unlink(missing_ok=True)
        raise
    if originals: print('Резервная копия:', backup)
    print('Web 1.5 установлен. Выполните Maven test, затем перезапустите run-web.ps1 и Ctrl+F5.')


if __name__ == '__main__':
    try: deploy()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:', ex, file=sys.stderr)
        raise SystemExit(1)
