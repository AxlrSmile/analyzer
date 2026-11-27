#!/usr/bin/env python3
"""Web 1.8 version-locked patch. Reject conflicts before writes; back up and roll back changes."""
from pathlib import Path
from datetime import datetime
import hashlib, os, shutil, sys
ROOT=Path(__file__).resolve().parent
PAYLOAD=ROOT/'web-v18-files'
BASELINE_HASHES={'src/main/resources/static/index.html': '7f1b2e44986e94b02ebdf422acd38155ecf8ae9293344b6e26395b43017d828d', 'src/main/resources/static/web.js': '789a95b014c11b6f99697af29351c3fef5f73f67b7c17552d7ec21b5b120414c', 'src/main/resources/static/web.css': '9aeae765e70a38cf9557ab1c27635bf2694dea8d94fb0b5771f47ef7f5319321', 'src/main/java/com/analyzerweb/WebFixService.java': '85b77ab5150003652de37debafc09cf2bec54046d665f08ab243b239ee2ae102'}
PAYLOAD_HASHES={'src/main/resources/static/index.html': '25171110ca9f32d71d326ec1b35f1ae4ccd29f24927bf5dde0887df977491b68', 'src/main/resources/static/web.js': '324e7c86cd70580f88dc7fd5a93df52bfc52234c0340dfb88002d02c992adf33', 'src/main/resources/static/web.css': 'dedced8c774ac998b94b7f044969973b8ca2c545acef813d3312f4be82c3b8e8', 'src/main/resources/static/web-fix-review.js': '33ca007c87e92d150a5c65f9119780ce16fd430df6338117d5183a50066f3528', 'src/main/java/com/analyzerweb/WebFixService.java': 'eeb04dcd71dd19f14763e39f68c6a467eb8053b79d133d4fcf8151c20e608594', 'src/main/java/com/analyzerweb/WebFixComparison.java': '3a5f4f27e632ff8c3d7db1f55ec6ecbc1fad4716b5efdb7ce0c01d29d0fd4c73', 'src/test/java/com/analyzerweb/WebFixComparisonTest.java': '4fbd8653a432887f7d1cd401fd10c6d02c346fe349bb86ec96849dcec2c6d543', 'benchmark-dataset/evaluate_web_v18.py': '7e2d4226d0740377e88350d8a378da4f6d117447b5e9734370934911f0ed01fc'}
REQUIRED_HASHES={'src/main/resources/static/web-dashboard.js': 'de1ea3e92d81c368973fb81fed03c7329c42fcbf732f53e7a1afab1e50fb07e5', 'src/main/resources/static/web-diagnostics.js': '26e7807ea9fab66a4c0c36f229fdfba2f4b6ad0a4f921fab9cd44aba0015c8fe'}

def sha(b):return hashlib.sha256(b).hexdigest()
def regular(p):return p.is_file() and not p.is_symlink()
def parents_are_safe(rel):
    node=ROOT
    for name in rel.parts[:-1]:
        node=node/name
        if node.is_symlink():raise RuntimeError('Недопустимый символический путь: '+str(rel))
def plan():
    if not regular(ROOT/'pom.xml'):raise RuntimeError('Распакуйте ZIP рядом с pom.xml')
    for name,expected in REQUIRED_HASHES.items():
        dst=ROOT/name;parents_are_safe(Path(name))
        if not regular(dst) or sha(dst.read_bytes())!=expected:
            raise RuntimeError('Требуется точная Web 1.7 (или файл изменён): '+name)
    changes={}
    for name,expected in PAYLOAD_HASHES.items():
        rel=Path(name);parents_are_safe(rel)
        source=PAYLOAD/rel;target=ROOT/rel
        if not regular(source) or sha(source.read_bytes())!=expected:
            raise RuntimeError('Архив повреждён или изменён: '+name)
        if target.exists():
            if not regular(target):raise RuntimeError('Конфликт типа файла: '+name)
            current=sha(target.read_bytes())
            if current==expected:continue
            if current!=BASELINE_HASHES.get(name):
                raise RuntimeError('КОНФЛИКТ: локальный файл отличается от ожидаемой Web 1.7: '+name)
        elif name in BASELINE_HASHES:
            raise RuntimeError('Не найден обязательный файл Web 1.7: '+name)
        changes[rel]=source.read_bytes()
    return changes

def install():
    changes=plan()
    if not changes:
        print('Web 1.8 уже установлен; файлы не изменены.')
        return
    backup=ROOT/'web-v18-backup'/datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    originals={}
    for rel in changes:
        dst=ROOT/rel
        if dst.exists():
            originals[rel]=dst.read_bytes()
            saved=backup/rel;saved.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(dst,saved)
    written=[]
    try:
        for rel,data in changes.items():
            dest=ROOT/rel;dest.parent.mkdir(parents=True,exist_ok=True)
            temp=dest.with_name(dest.name+'.tmp-web18')
            try:
                temp.write_bytes(data);os.replace(temp,dest)
            finally:temp.unlink(missing_ok=True)
            written.append(rel)
            print('Установлено:',rel)
    except Exception:
        for rel in reversed(written):
            dest=ROOT/rel
            if rel in originals:dest.write_bytes(originals[rel])
            else:dest.unlink(missing_ok=True)
        raise
    if originals:print('Резервные копии:',backup)
    print('Web 1.8 установлен. Проверьте Maven на JDK 21 и перезапустите сервер.')

if __name__=='__main__':
    try:install()
    except Exception as ex:
        print('ОСТАНОВЛЕНО:',ex,file=sys.stderr);sys.exit(1)
