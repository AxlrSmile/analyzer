#!/usr/bin/env python3
"""Install UI dashboard polish on top of the previously installed UI theme patch.

Safety: preflight all sources, reject conflicting edits, backup changed files,
then apply only JavaFX bootstrap, theme CSS and the new presentation layer.
Never changes MainController, agent services, reports or repository metadata.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "src" / "main"
PAYLOAD = ROOT / "ui-dashboard-files" / "src" / "main"
APP = BASE / "java" / "com" / "analyzer" / "JavaFxApplication.java"
IMPORT = "import com.analyzer.ui.theme.UiDashboardEnhancer;"
CALL = "        UiDashboardEnhancer.install(primaryStage, root);"
OLD_CALL = "        UiAppearanceManager.install(primaryStage, root);"
OLD_IMPORT = "import com.analyzer.ui.theme.UiAppearanceManager;"
REL = [
    Path("java/com/analyzer/ui/theme/UiDashboardEnhancer.java"),
    Path("resources/styles/web-light.css"),
    Path("resources/styles/web-dark.css"),
    Path("resources/styles/light-theme.css"),
    Path("resources/styles/dark-theme.css"),
]
# These are the checksums from the FIRST theme patch. Only unmodified previous
# themes or already-installed v2 themes may be replaced automatically.
OLD_THEME_SHA256 = {
    "light-theme.css": "e30f3b4ab1e34a42a598e4c6ac2ebc681beaf291d07f788ffef50b0e682ec992",
    "dark-theme.css": "e6c7481e522d9d8419ecda8c0d66ac591520bffb5a0c1fca269021528154c84b",
}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fail(message: str) -> int:
    print("ОШИБКА: " + message, file=sys.stderr)
    print("Файлы проекта не изменены.", file=sys.stderr)
    return 1


def main() -> int:
    if not (ROOT / "pom.xml").is_file() or not APP.is_file():
        return fail("Распакуйте содержимое ZIP в code-security-analyzer рядом с pom.xml")

    for rel in REL:
        if not (PAYLOAD / rel).is_file():
            return fail(f"В ZIP отсутствует {PAYLOAD / rel}")

    app_old = APP.read_text(encoding="utf-8-sig")
    if app_old.count(OLD_IMPORT) != 1 or app_old.count(OLD_CALL) != 1:
        return fail("Сначала установите предыдущий UI-патч с UiAppearanceManager")
    already = app_old.count(IMPORT) == 1 and app_old.count(CALL) == 1
    if not already and (IMPORT in app_old or CALL in app_old):
        return fail("Обнаружено неполное изменение JavaFxApplication.java")
    if app_old.count("import com.analyzer.config.SpringFXMLLoader;") != 1:
        return fail("Не найдена ожидаемая точка подключения импорта")

    if already:
        app_new = app_old
    else:
        app_new = app_old.replace(
            "import com.analyzer.config.SpringFXMLLoader;",
            "import com.analyzer.config.SpringFXMLLoader;\n" + IMPORT,
            1,
        ).replace(OLD_CALL, OLD_CALL + "\n" + CALL, 1)

    planned: dict[Path, bytes] = {APP: app_new.encode("utf-8")}
    for rel in REL:
        target = BASE / rel
        desired = (PAYLOAD / rel).read_bytes()
        if target.exists():
            current = target.read_bytes()
            if current != desired:
                # Only the original known theme version can be upgraded in-place.
                if rel.name in OLD_THEME_SHA256:
                    if sha256(current) != OLD_THEME_SHA256[rel.name]:
                        return fail(f"Тема изменена вручную: {rel}. Обновление остановлено")
                else:
                    return fail(f"Существует другой файл: {rel}. Обновление остановлено")
        planned[target] = desired

    changed = [(dst, data) for dst, data in planned.items()
               if not dst.is_file() or dst.read_bytes() != data]
    if not changed:
        print("UI Dashboard уже установлен, повторных изменений нет.")
        return 0

    backup = ROOT / "ui-theme-backup" / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-dashboard")
    backup.mkdir(parents=True, exist_ok=False)
    for dst, _ in changed:
        if dst.exists():
            relative = dst.relative_to(ROOT)
            copy = backup / relative
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, copy)
    print(f"Резервные копии изменяемых файлов: {backup}")

    written: list[Path] = []
    try:
        for dst, data in changed:
            dst.parent.mkdir(parents=True, exist_ok=True)
            temp = dst.with_name(dst.name + ".dashboard.tmp")
            temp.write_bytes(data)
            os.replace(temp, dst)
            written.append(dst)
            print("Обновлено: " + str(dst.relative_to(ROOT)))
    except Exception as ex:
        # Roll back all successful writes, without touching files not in this patch.
        for dst in reversed(written):
            previous = backup / dst.relative_to(ROOT)
            if previous.exists():
                shutil.copy2(previous, dst)
            else:
                dst.unlink(missing_ok=True)
        return fail("Ошибка установки, изменения отменены: " + str(ex))

    print("Готово. Проверьте JDK 21, Maven-тесты, затем обе темы и WebView.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
