#!/usr/bin/env python3
"""Guarded Web 1.4 install over exact Web 1.3; leaves JavaFX/REST/agents unchanged."""
from pathlib import Path
from datetime import datetime
import hashlib, os, shutil, sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'web-v14-files'
OLD_HASHES = {'src/main/resources/static/index.html': '25b58cfb4dda0c1b46fa547d55337fdadf46575691a0eb48ecd9aa220f0151f0', 'src/main/resources/static/web.js': '33ecd0555ff219a2e3f39b7a49b1d3d7b88f52ce7fe82fe1f0602a0b92b25818', 'src/main/resources/static/web.css': '3e2fb4b5cfe7bb8cbcd4e9ab23f95a35f39537d1a990c3e68fe779c7e0e29ca5'}
NEW_HASHES = {'src/main/resources/static/web.js': '263ba07c002829621111f554ebd4eba65f618eaf44e3bcaa9fe8c743dd5ce9d8', 'src/main/resources/static/web.css': 'fa37aaac95350606b9a123c890550769f5734b392d3b50a967c0291e7edee484', 'src/main/resources/static/index.html': 'c64aae1b88b6863174c307d6731d4b6ea280be5e268dc4ff4817f6913ee96af4', 'src/main/resources/static/web-insights.js': '3904a2176b476a7ef001c8ad680fc9465ad223dd1c6577ae1cb7a56ea44027d8'}

def sha(b): return hashlib.sha256(b).hexdigest()

def install():
    if not (ROOT/'pom.xml').is_file():
        raise RuntimeError('Распакуйте ZIP в корень code-security-analyzer рядом с pom.xml')
    for required in ('src/main/resources/static/web-journal.js',
                     'src/main/java/com/analyzerweb/WebFixController.java'):
        if not (ROOT/required).is_file():
            raise RuntimeError('Не найдена установленная Web 1.3: '+required)
    changes=[]
    for relative, expected in NEW_HASHES.items():
        source=PAYLOAD/relative
        if not source.is_file() or sha(source.read_bytes())!=expected:
            raise RuntimeError('Файлы обновления повреждены: '+relative)
        destination=ROOT/relative
        if destination.is_symlink():
            raise RuntimeError('КОНФЛИКТ: ссылка вместо файла: '+relative)
        if not destination.exists():
            if relative in OLD_HASHES:
                raise RuntimeError('Отсутствует исходный файл Web 1.3: '+relative)
            changes.append((source,destination))
            continue
        if not destination.is_file():
            raise RuntimeError('КОНФЛИКТ: путь не является файлом: '+relative)
        actual=sha(destination.read_bytes())
        if actual==expected: continue
        if actual==OLD_HASHES.get(relative): changes.append((source,destination))
        else: raise RuntimeError('КОНФЛИКТ: локально изменён '+relative+'. Ничего не перезаписано.')
    if not changes:
        print('Web 1.4 уже установлен. Повторные изменения не требуются.');return
    prior=[(source,dest) for source,dest in changes if dest.exists()]
    backups=ROOT/'web-v14-backup'/datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    for _,dst in prior:
        target=backups/dst.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(dst,target)
    if prior: print('Резервная копия:',backups)
    installed=[]
    try:
        for src,dst in changes:
            dst.parent.mkdir(parents=True,exist_ok=True)
            tmp=dst.with_name(dst.name+'.tmp-web14')
            try:
                shutil.copyfile(src,tmp)
                os.replace(tmp,dst)
            finally:
                tmp.unlink(missing_ok=True)
            installed.append(dst)
            print('Установлено:',dst.relative_to(ROOT))
    except Exception:
        for dst in reversed(installed):
            saved=backups/dst.relative_to(ROOT)
            if saved.is_file(): shutil.copy2(saved,dst)
            else: dst.unlink(missing_ok=True)
        raise
    print('Web 1.4 установлен. Перезапустите run-web.ps1, откройте Ctrl+F5.')

if __name__=='__main__':
    try: install()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:',ex,file=sys.stderr)
        raise SystemExit(1)
