#!/usr/bin/env python3
"""Fix UI v7 deferred NullPointerException by lazy TreeView discovery.

Only UiPolishV5.java is changed; existing scanners, models, reports, FXML and CSS untouched.
Aborts on unexpected file contents. Writes UTF-8 without BOM. Creates a timestamped backup.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
DEST = ROOT / "src/main/java/com/analyzer/ui/theme/UiPolishV5.java"
V7 = ROOT / "ui-v8-files/UiPolishV5.v7.java"
V8 = ROOT / "ui-v8-files/UiPolishV5.java"


def canonical_bytes(path: Path) -> bytes:
    # Normalize only for version comparison; writes use the reviewed UTF-8 resource.
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n").encode("utf-8")


def main() -> int:
    if not (ROOT / "pom.xml").is_file():
        print("ОШИБКА: поместите содержимое ZIP в корень проекта рядом с pom.xml.", file=sys.stderr)
        return 1
    if not DEST.is_file() or not V7.is_file() or not V8.is_file():
        print("ОШИБКА: не найдены UiPolishV5.java или файлы обновления.", file=sys.stderr)
        return 1
    try:
        current = canonical_bytes(DEST)
        desired = canonical_bytes(V8)
        expected = canonical_bytes(V7)
        if current == desired:
            print("UI Filter v8 уже установлен. Изменения не требуются.")
            return 0
        if current != expected:
            print("ОСТАНОВЛЕНО: UiPolishV5.java не совпадает с ожидаемой версией v7.", file=sys.stderr)
            print("Файл оставлен без изменений. Не удаляйте резервные копии; пришлите UiPolishV5.java для точечного исправления.", file=sys.stderr)
            return 2
        backup = (ROOT / "ui-theme-backup" /
                  (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-filter-v8"))
        backup.mkdir(parents=True, exist_ok=False)
        saved = backup / "UiPolishV5.java"
        shutil.copy2(DEST, saved)
        tmp = DEST.with_name(DEST.name + ".filter-v8.tmp")
        try:
            tmp.write_bytes(desired)
            os.replace(tmp, DEST)
        except OSError:
            shutil.copy2(saved, DEST)
            raise
        finally:
            if tmp.exists():
                tmp.unlink()
        print("Исправлено: src/main/java/com/analyzer/ui/theme/UiPolishV5.java")
        print("Резервная копия:", saved)
        print("UI v8: отложенный поиск дерева, проверка null, подключение фильтра только после доступности TreeView.")
        return 0
    except (OSError, UnicodeError) as exc:
        print("ОШИБКА установки:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
