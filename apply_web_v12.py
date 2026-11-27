#!/usr/bin/env python3
"""Install Web 1.2 on exact Web 1.1. Guarded install; desktop untouched."""
from pathlib import Path
from datetime import datetime
import hashlib, os, shutil, sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'web-v12-files'
OLD_HASHES = {'src/main/resources/static/index.html': '919c69f366256706518ac1df586866bf5fbb55d76ba6aaa3a18cf577317beb28', 'src/main/resources/static/web.css': '25221745ffcf2e8482dfd162e3a074710d5779e895039b188c8a2aafe96745dd', 'src/main/resources/static/web.js': 'd6431e67b0f2137dc2e9d2b1e4ce0cc50b7df66b56e3d26b742d4fd4dde87fb0'}
NEW_HASHES = {'src/main/java/com/analyzerweb/WebFixController.java': 'f488cebff75770676d171f9b5fac0b1f5f0374f59236419ec5c3b15b8cc42d21', 'src/main/java/com/analyzerweb/WebFixPolicy.java': '4886d63df68cbb4346ce27885335d9fd2c76aea193ac502222dcf4cdb93a77b7', 'src/main/java/com/analyzerweb/WebFixService.java': '85b77ab5150003652de37debafc09cf2bec54046d665f08ab243b239ee2ae102', 'src/main/resources/static/index.html': '616d1a34dece58e27106838beddee81802823c632ecb8b5b216900a347b483f9', 'src/main/resources/static/web.css': '0a2abf2346ebd6ae596ff6a0daaeb0ac63c54385fc6d8ef983ff81f400752fd1', 'src/main/resources/static/web.js': '8b76ce4e72c4bb41c67edade087212014091e98cb65257890a6608968318a8d8', 'src/test/java/com/analyzerweb/WebFixPolicyTest.java': 'f4eeaf5371cfce82255b4bc7ef0747d5ae899f37b8a179e9625c56a1648a719a'}

def sha(content):
    return hashlib.sha256(content).hexdigest()

def run():
    if not (ROOT/'pom.xml').is_file():
        raise RuntimeError('Распакуйте патч в корень code-security-analyzer рядом с pom.xml')
    if not (ROOT/'src/main/java/com/analyzerweb/WebServerApplication.java').is_file():
        raise RuntimeError('Сначала установите Web 1.0 и Web 1.1')
    changes=[]
    for relative, expected in NEW_HASHES.items():
        src=PAYLOAD/relative
        if not src.is_file() or sha(src.read_bytes()) != expected:
            raise RuntimeError('Повреждён файл в патче: '+relative)
        dest=ROOT/relative
        if not dest.exists():
            if relative in OLD_HASHES:
                raise RuntimeError('Сначала установите Web 1.1, отсутствует: '+relative)
            changes.append((src,dest))
        else:
            digest=sha(dest.read_bytes())
            if digest==expected: continue
            if digest==OLD_HASHES.get(relative):
                changes.append((src,dest))
            else:
                raise RuntimeError('КОНФЛИКТ: '+relative+' изменён локально. Ничего не перезаписано.')
    if not changes:
        print('Web 1.2 уже установлен; повторных изменений нет.')
        return
    backups=[(src,dest) for src,dest in changes if dest.exists()]
    if backups:
        directory=ROOT/'web-v12-backup'/datetime.now().strftime('%Y%m%d-%H%M%S')
        for _,dest in backups:
            backup=directory/dest.relative_to(ROOT)
            backup.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(dest,backup)
        print('Резервная копия:',directory)
    for src,dest in changes:
        dest.parent.mkdir(parents=True,exist_ok=True)
        staging=dest.with_name(dest.name+'.tmp-web12')
        try:
            shutil.copyfile(src,staging)
            os.replace(staging,dest)
        finally:
            staging.unlink(missing_ok=True)
        print('Установлено:',dest.relative_to(ROOT))
    print('Web 1.2 установлен. Выполните Maven-тесты и запустите run-web.ps1.')

if __name__=='__main__':
    try: run()
    except Exception as e:
        print('ОСТАНОВЛЕНО:',str(e),file=sys.stderr)
        raise SystemExit(1)
