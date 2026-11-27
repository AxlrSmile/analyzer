#!/usr/bin/env python3
"""Install Code Security Analyzer Web 1.1 on top of the exact Web 1.0 build.
Refuses unknown edits, makes backups; leaves desktop UI and build configuration untouched.
"""
from pathlib import Path
from datetime import datetime
import hashlib
import shutil
import sys

ROOT=Path(__file__).resolve().parent
PAYLOAD=ROOT / 'web-v11-files'
OLD_HASHES={'src/main/java/com/analyzerweb/WebApiController.java': '22a9e2ba87297dcffda30bdfed6b51aa1499f66be2c112670db2818b19d9e174', 'src/main/java/com/analyzerweb/WebScanService.java': '92922045e29f51949010e14a8b5f527aabbbb889f3d737a0a99d4c184a448fdb', 'src/main/resources/static/index.html': '7f123b8f4aca9b4f848ca4972bb33998e8ec60bdbe533c830af19a8bb072d1a8', 'src/main/resources/static/web.js': '172a15dbf8fbc7f8f778664dc8faa04618528b3abbb9daa7e6eac85518b27c3b', 'src/main/resources/static/web.css': '7bb9a210a83cb77f1769b1fea00743423b08c295213055abac6c2f90f8dab0e1', 'src/main/resources/application-web.properties': '9a5ddb574cd8734adf9588c36f2e9c60fbd1baafbbe80be4469dc0f96d410972'}
NEW_HASHES={'src/main/java/com/analyzerweb/WebApiController.java': 'a43799a5a9143f51447f35919ad1b1943c44341dc1c09c5215282582f45af87e', 'src/main/java/com/analyzerweb/WebScanService.java': '3b884e8ab57ae2b170fb9775a1d3598dda605c7bca2c69e185528c0870c94e85', 'src/main/resources/static/index.html': '919c69f366256706518ac1df586866bf5fbb55d76ba6aaa3a18cf577317beb28', 'src/main/resources/static/web.js': 'd6431e67b0f2137dc2e9d2b1e4ce0cc50b7df66b56e3d26b742d4fd4dde87fb0', 'src/main/resources/static/web.css': '25221745ffcf2e8482dfd162e3a074710d5779e895039b188c8a2aafe96745dd', 'src/main/resources/application-web.properties': '6e67543d8837867f94eba9c0e82517a2c93aedb11311caf3adb86d5675893b22', 'src/main/java/com/analyzerweb/WebZipPolicy.java': '2a07c3d7cfb6ed0188b0900586ef554370aacd3da090358d156fa5ae16ae54af', 'src/test/java/com/analyzerweb/WebZipPolicyTest.java': 'ae3c5a7baa2d4a0e28ae214353113c95d141ab7d0c62dca3b5d29119542906e6'}

def sha(data): return hashlib.sha256(data).hexdigest()

def main():
    if not (ROOT / 'pom.xml').is_file():
        raise RuntimeError('Распакуйте архив в корень code-security-analyzer рядом с pom.xml')
    updates=[]
    additions=[]
    for relative, expected in NEW_HASHES.items():
        target=ROOT / relative
        source=PAYLOAD / relative
        if not source.is_file() or sha(source.read_bytes()) != expected:
            raise RuntimeError('Архив повреждён: ' + relative)
        if target.exists():
            actual=sha(target.read_bytes())
            if actual == expected: continue
            if actual == OLD_HASHES.get(relative): updates.append((source,target))
            else: raise RuntimeError('КОНФЛИКТ: файл изменён вручную: ' + relative + '. Ничего не перезаписано.')
        else:
            if relative in OLD_HASHES:
                raise RuntimeError('Сначала установите Web 1.0: отсутствует ' + relative)
            additions.append((source,target))
    if not updates and not additions:
        print('Web 1.1 уже установлен — изменений нет.')
        return
    backup = ROOT / 'web-v11-backup' / datetime.now().strftime('%Y%m%d-%H%M%S')
    for _,target in updates:
        destination=backup / target.relative_to(ROOT)
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(target,destination)
    print('Резервная копия изменяемых файлов:',backup)
    for source,target in updates+additions:
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target)
        print('Обновлён:',target.relative_to(ROOT))
    print(r'Web 1.1 установлен. Запустите .\mvnw.cmd clean test и .\run-web.ps1')

if __name__=='__main__':
    try: main()
    except Exception as ex:
        print('ОСТАНОВЛЕНО: '+str(ex),file=sys.stderr)
        sys.exit(1)
