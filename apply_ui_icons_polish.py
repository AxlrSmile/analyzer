#!/usr/bin/env python3
"""Safe, idempotent JavaFX UI icons v3 upgrade (requires theme v1 + dashboard v2).

Changes JavaFX bootstrap, the two known v2 theme CSS files and adds a vector
icon presentation class + window icon. The original code audit/services are untouched.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "main"
PAYLOAD = ROOT / "ui-icons-files" / "src" / "main"
APP = SRC / "java" / "com" / "analyzer" / "JavaFxApplication.java"
IMPORT_ANCHOR = "import com.analyzer.ui.theme.UiDashboardEnhancer;"
CALL_ANCHOR = "        UiDashboardEnhancer.install(primaryStage, root);"
NEW_IMPORT = "import com.analyzer.ui.theme.UiIconPolish;"
NEW_CALL = "        UiIconPolish.install(primaryStage, root);"
RELATIVE = [
    Path("java/com/analyzer/ui/theme/UiIconPolish.java"),
    Path("resources/images/app-shield.png"),
    Path("resources/styles/light-theme.css"),
    Path("resources/styles/dark-theme.css"),
]
PRIOR_THEME_DIGESTS = {
    "light-theme.css": "028ff14cff3853385db740131c2d8dc44c1c05a998c1715248d3bb94586a8fd2",
    "dark-theme.css": "2d32eb46419a658c1b35a665c2304692f2265c248150f30a2609fdfdc0e7afed",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject(reason: str) -> int:
    print("УСТАНОВКА ОСТАНОВЛЕНА: " + reason, file=sys.stderr)
    print("Исходники проекта не изменены.", file=sys.stderr)
    return 1


def main() -> int:
    if not (ROOT / "pom.xml").is_file() or not APP.is_file():
        return reject("Распакуйте ZIP в корень code-security-analyzer рядом с pom.xml")
    for rel in RELATIVE:
        if not (PAYLOAD / rel).is_file():
            return reject(f"Не найден файл патча: {rel}")
    if not (SRC / "java/com/analyzer/ui/theme/UiAppearanceManager.java").is_file():
        return reject("Сначала установите первый UI Theme/Responsive патч")
    if not (SRC / "java/com/analyzer/ui/theme/UiDashboardEnhancer.java").is_file():
        return reject("Сначала установите UI Dashboard Polish патч")
    app_old = APP.read_text(encoding="utf-8-sig")
    if app_old.count(IMPORT_ANCHOR) != 1 or app_old.count(CALL_ANCHOR) != 1:
        return reject("Не найдены ожидаемые строки подключения Dashboard в JavaFxApplication.java")
    imported = app_old.count(NEW_IMPORT)
    called = app_old.count(NEW_CALL)
    if (imported != called or imported > 1):
        return reject("Неполная или конфликтующая установка UiIconPolish")
    if imported:
        app_new = app_old
    else:
        app_new = app_old.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "\n" + NEW_IMPORT, 1)
        app_new = app_new.replace(CALL_ANCHOR, CALL_ANCHOR + "\n" + NEW_CALL, 1)

    requested: dict[Path, bytes] = {APP: app_new.encode("utf-8")}
    for rel in RELATIVE:
        target = SRC / rel
        desired = (PAYLOAD / rel).read_bytes()
        if target.exists() and target.read_bytes() != desired:
            # Only known, untouched v2 themes may be upgraded in place.
            if rel.name not in PRIOR_THEME_DIGESTS or digest(target.read_bytes()) != PRIOR_THEME_DIGESTS[rel.name]:
                return reject(f"Существует конфликтующий/отредактированный файл: {rel}. "
                              "Сделайте отдельную копию и сверьте изменения вручную")
        requested[target] = desired
    changes = [(target, raw) for target, raw in requested.items()
               if not target.exists() or target.read_bytes() != raw]
    if not changes:
        print("UI Icons Polish v3 уже установлен. Ничего не изменено.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = ROOT / "ui-theme-backup" / f"{stamp}-icons-v3"
    try:
        backup.mkdir(parents=True, exist_ok=False)
        for target, _ in changes:
            if target.exists():
                old_copy = backup / target.relative_to(ROOT)
                old_copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, old_copy)
    except Exception as exc:
        return reject("Не удалось сохранить резервные копии: " + str(exc))
    print("Резервные копии: " + str(backup))

    written: list[Path] = []
    try:
        for target, raw in changes:
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = target.with_name(target.name + ".icons-v3.tmp")
            temp.write_bytes(raw)
            os.replace(temp, target)
            written.append(target)
            print("Установлен: " + str(target.relative_to(ROOT)))
    except Exception as exc:
        for target in reversed(written):
            previous = backup / target.relative_to(ROOT)
            if previous.is_file():
                shutil.copy2(previous, target)
            else:
                target.unlink(missing_ok=True)
        return reject("Ошибка копирования; изменения отменены: " + str(exc))

    print("Успешно установлен UI Icons Polish v3. Далее JDK 21, Maven и проверка JavaFX.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
