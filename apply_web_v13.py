#!/usr/bin/env python3
"""Guarded Web 1.3 install over exact Web 1.2; creates backups, no Maven rewrite."""
from pathlib import Path
from datetime import datetime
import hashlib, os, shutil, sys

ROOT=Path(__file__).resolve().parent
PAYLOAD=ROOT/'web-v13-files'
OLD_HASHES={'src/main/resources/static/index.html': '616d1a34dece58e27106838beddee81802823c632ecb8b5b216900a347b483f9',
 'src/main/resources/static/web.css': '0a2abf2346ebd6ae596ff6a0daaeb0ac63c54385fc6d8ef983ff81f400752fd1',
 'src/main/resources/static/web.js': '8b76ce4e72c4bb41c67edade087212014091e98cb65257890a6608968318a8d8'}
NEW_HASHES={'src/main/resources/static/index.html': '25b58cfb4dda0c1b46fa547d55337fdadf46575691a0eb48ecd9aa220f0151f0',
 'src/main/resources/static/web-journal.js': '809bece8239e94c9497d57136f4141315361c77456ce481d87a35cfe923224af',
 'src/main/resources/static/web.css': '3e2fb4b5cfe7bb8cbcd4e9ab23f95a35f39537d1a990c3e68fe779c7e0e29ca5',
 'src/main/resources/static/web.js': '33ecd0555ff219a2e3f39b7a49b1d3d7b88f52ce7fe82fe1f0602a0b92b25818'}

def sha(content):
    return hashlib.sha256(content).hexdigest()

def install():
    if not (ROOT/'pom.xml').is_file():
        raise RuntimeError('Распакуйте ZIP в корень code-security-analyzer рядом с pom.xml')
    for item in ('src/main/java/com/analyzerweb/WebFixController.java',
                 'src/main/java/com/analyzerweb/WebFixService.java',
                 'src/main/resources/static/web.js'):
        if not (ROOT/item).is_file():
            raise RuntimeError('Не найдена Web 1.2. Установите Web 1.2 перед v1.3: '+item)
    changes=[]
    # Preflight ALL files before writing ANY file.
    for relative, expected in NEW_HASHES.items():
        source=PAYLOAD/relative
        if not source.is_file() or sha(source.read_bytes()) != expected:
            raise RuntimeError('Патч повреждён: '+relative)
        destination=ROOT/relative
        if not destination.exists():
            if relative in OLD_HASHES:
                raise RuntimeError('Отсутствует файл Web 1.2: '+relative)
            changes.append((source,destination))
            continue
        if not destination.is_file():
            raise RuntimeError('КОНФЛИКТ: путь не является файлом: '+relative)
        actual=sha(destination.read_bytes())
        if actual==expected:continue
        if actual==OLD_HASHES.get(relative):
            changes.append((source,destination))
        else:
            raise RuntimeError('КОНФЛИКТ: локально изменён '+relative+'. Ничего не перезаписано.')
    if not changes:
        print('Web 1.3 уже установлен. Повторных изменений нет.');return
    existing=[dst for _,dst in changes if dst.exists()]
    if existing:
        backups=ROOT/'web-v13-backup'/datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        for dst in existing:
            backup=backups/dst.relative_to(ROOT)
            backup.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(dst,backup)
        print('Резервная копия:',backups)
    for src,dst in changes:
        dst.parent.mkdir(parents=True,exist_ok=True)
        tmp=dst.with_name(dst.name+'.tmp-web13')
        try:
            shutil.copyfile(src,tmp)
            os.replace(tmp,dst)
        finally:
            tmp.unlink(missing_ok=True)
        print('Установлено:',dst.relative_to(ROOT))
    print('Web 1.3 установлен. Перезапустите run-web.ps1 и откройте сайт с Ctrl+F5.')

if __name__=='__main__':
    try:install()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:',ex,file=sys.stderr)
        raise SystemExit(1)
