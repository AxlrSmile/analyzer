#!/usr/bin/env python3
"""Web 1.6 offline exact-version patch on top of Web 1.5.
- refuses unknown versions before writing
- preserves JavaFX, source files, audit browser storage, test dataset
- backs up replaced files and rolls back partial installs
"""
from datetime import datetime
from pathlib import Path
import hashlib
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'web-v16-files'
CORE = Path('src/main/java/com/analyzer/service/ai/OllamaClient.java')
BASELINE_HASHES = {'src/main/java/com/analyzerweb/WebFindingDiagnostics.java': '915c37013cbbc548311e174aa766e344c592394350e6c2181eabca888ccf5b75', 'src/main/resources/static/web-insights.js': '0d190802f972513b72cfad21222a293684382abc843b347c8fb910f17438e998', 'src/main/resources/static/web-diagnostics.js': '74e8061e149affc23e07d888c261ee7d8303c19ee91d6caf0ee62bd4cea8555a', 'src/main/resources/static/web.css': '7bd2ab18f911b2ad875f7c9f67a059db8d6bd48d65c4f19406193c1d172032ac', 'src/main/resources/static/index.html': '9c3067dd8dc0af3daaf7b9082db2b70305cdb5abaf57c7279fa55758dd8c47e2', 'src/main/resources/static/web.js': 'f6df6aad578b3f4482750ace80cc859689961a764d79b7069ce68c77addce5b4', 'src/test/java/com/analyzerweb/WebFindingDiagnosticsTest.java': 'db2862f8b8f22d2e65e862aa2833b7fe36ed02d7c79e6c363673e689244fa41f'}
PAYLOAD_HASHES = {'src/main/java/com/analyzerweb/WebFindingDiagnostics.java': '0cd912187d6e68ee14bbe7e9afe0514e1d5ccf8d139b1d4fb9db2fa22f823d96', 'src/main/java/com/analyzer/service/ai/EvidenceRetryHints.java': 'b116871def7895bfc6df32d99a96b475b34f7c21ce84831542327886cba479f8', 'src/main/resources/static/web-insights.js': 'a3f05a4d2366644433b8b6679df4b47f7b7232eddaddce71b27922416f9872cb', 'src/main/resources/static/web-diagnostics.js': '26e7807ea9fab66a4c0c36f229fdfba2f4b6ad0a4f921fab9cd44aba0015c8fe', 'src/main/resources/static/web.css': '47ba5d86f2ebddc3a9739aa3d75e315f553a355e464166768cf5ce439bb2259e', 'src/main/resources/static/index.html': '2d0b2331da9a8d5aaf27a5d95c0ed793724fdc841c65de5f85f0c4ff33a6cb05', 'src/main/resources/static/web.js': '7e7a671d72e8213ef877a3391ea134c73c77f2d0793f4decc37c7d4ed22a2119', 'src/test/java/com/analyzerweb/WebFindingDiagnosticsTest.java': '20d5d3283bd9afbd0557224996fa206de41019409dd531b032743ea8efbd6806', 'src/test/java/com/analyzer/service/ai/OllamaContextRetryIntegrationTest.java': 'e1f89754582d6c585c320c73884832083c4862b800bebfe73e876a95e01a51ae', 'src/test/java/com/analyzer/service/ai/EvidenceRetryHintsTest.java': 'd08516bbd1fcbd73aa8df216b6894a56c85725f4ea5b8d4543852f848b397c8b'}
OLD_RETRY = '            // WEB15_EVIDENCE_RETRY: targeted guidance; still only two attempts.\n            boolean evidenceProblem = lastValidationFailure.contains("evidence")\n                    || lastValidationFailure.contains("цитат");\n            String retryAdvice = evidenceProblem\n                    ? "ЦИТАТА: открой исходный блок с L-номерами; возьми точную непрерывную "\n                    + "однострочную подстроку из указанного L-номера. Не пиши Lномер | в evidence, "\n                    + "не сокращай код, не добавляй многоточия и не выдумывай строки. "\n                    : "СТРУКТУРА: проверь обязательные поля, целые номера строк и корректный CWE. ";\n            String currentPrompt = attempt == 0 ? prompt : prompt + "\\n\\n"\n                    + "ПОВТОРНЫЙ ЗАПРОС: предыдущий ответ не прошёл проверку: "\n                    + lastValidationFailure + ". " + retryAdvice\n                    + "Все startLine/endLine — абсолютные номера исходных L-строк. "\n                    + "Сохрани обоснованные находки, не заменяй их пустым списком. Верни только JSON.";'
NEW_RETRY = '            // WEB16_CONTEXT_RETRY: narrowly scoped original-line hint for failed citations.\n            // A hint does NOT certify an LLM finding; StructuredEvidencePreflight still checks it.\n            boolean evidenceProblem = lastValidationFailure.contains("evidence")\n                    || lastValidationFailure.contains("цитат");\n            String retryAdvice = evidenceProblem\n                    ? "ЦИТАТА: открой исходный блок с L-номерами; возьми точную непрерывную "\n                    + "однострочную подстроку из указанного L-номера. Не пиши Lномер | в evidence, "\n                    + "не сокращай код, не добавляй многоточия и не выдумывай строки. "\n                    : "СТРУКТУРА: проверь обязательные поля, целые номера строк и корректный CWE. ";\n            String contextHint = evidenceProblem && !invalidResponses.isEmpty()\n                    ? EvidenceRetryHints.build(numberedSource, invalidResponses.getFirst(), objectMapper)\n                    : "";\n            String currentPrompt = attempt == 0 ? prompt : prompt + "\\n\\n"\n                    + "ПОВТОРНЫЙ ЗАПРОС: предыдущий ответ не прошёл проверку: "\n                    + lastValidationFailure + ". " + retryAdvice\n                    + "Все startLine/endLine — абсолютные номера исходных L-строк. "\n                    + "Сохрани обоснованные находки, не заменяй их пустым списком. Верни только JSON."\n                    + contextHint;'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def patch_core(raw):
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as e:
        raise RuntimeError('OllamaClient.java должен быть в UTF-8') from e
    crlf = '\r\n' in text
    normalized = text.replace('\r\n', '\n')
    if 'WEB16_CONTEXT_RETRY' in normalized:
        if normalized.count('WEB16_CONTEXT_RETRY') != 1 or NEW_RETRY not in normalized:
            raise RuntimeError('Обнаружена неизвестная модификация Web 1.6 в OllamaClient.java')
        return raw
    if normalized.count(OLD_RETRY) != 1 or normalized.count('WEB15_EVIDENCE_RETRY') != 1:
        raise RuntimeError('Ожидался Web 1.5 OllamaClient.java; изменения не внесены')
    result = normalized.replace(OLD_RETRY, NEW_RETRY)
    if crlf: result = result.replace('\n', '\r\n')
    return result.encode('utf-8')


def install():
    if not (ROOT / 'pom.xml').is_file():
        raise RuntimeError('Распакуйте архив в корень проекта рядом с pom.xml')
    core_path = ROOT / CORE
    if not core_path.is_file() or core_path.is_symlink():
        raise RuntimeError('Не найден обычный файл OllamaClient.java')
    planned = {}
    for name, payload_sha in PAYLOAD_HASHES.items():
        rel = Path(name)
        src = PAYLOAD / rel
        dst = ROOT / rel
        if not src.is_file() or src.is_symlink() or sha(src.read_bytes()) != payload_sha:
            raise RuntimeError('Нарушена целостность архива: ' + name)
        if dst.is_symlink() or (dst.exists() and not dst.is_file()):
            raise RuntimeError('Конфликт пути: ' + name)
        if dst.exists():
            old = dst.read_bytes()
            if sha(old) == payload_sha: continue
            if sha(old) != BASELINE_HASHES.get(name):
                raise RuntimeError('КОНФЛИКТ: локальные изменения или неверная Web 1.5: ' + name)
        elif name in BASELINE_HASHES:
            raise RuntimeError('Не найден обязательный файл Web 1.5: ' + name)
        planned[rel] = src.read_bytes()
    core_old = core_path.read_bytes()
    core_new = patch_core(core_old)
    if core_new != core_old: planned[CORE] = core_new
    if not planned:
        print('Web 1.6 уже установлен. Ничего не изменено.')
        return
    # Before installation, check all parent segments for symlinks.
    for rel in planned:
        p = ROOT
        for part in rel.parts[:-1]:
            p = p / part
            if p.is_symlink(): raise RuntimeError('Конфликт: симлинк в пути ' + str(rel))
    backup = ROOT / 'web-v16-backup' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    originals = {}
    for rel in planned:
        dst = ROOT / rel
        if dst.exists():
            originals[rel] = dst.read_bytes()
            safe_backup = backup / rel
            safe_backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, safe_backup)
    completed = []
    try:
        for rel, raw in planned.items():
            dest = ROOT / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + '.tmp-web16')
            try:
                tmp.write_bytes(raw)
                os.replace(tmp, dest)
            finally:
                tmp.unlink(missing_ok=True)
            completed.append(rel)
            print('Установлено:', rel)
    except Exception:
        for rel in reversed(completed):
            dest = ROOT / rel
            if rel in originals: dest.write_bytes(originals[rel])
            else: dest.unlink(missing_ok=True)
        raise
    if originals: print('Резервная копия:', backup)
    print('Web 1.6 установлен. Запустите Maven test и перезапустите сервер.')


if __name__ == '__main__':
    try: install()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:', ex, file=sys.stderr)
        raise SystemExit(1)
