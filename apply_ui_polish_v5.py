#!/usr/bin/env python3
"""Install UI Polish v5 above v1-v4, with preflight, backups and rollback.

Presentation-only: adds a filter layer, fixes one broken welcome glyph, adds CSS.
Never modifies repository metadata, benchmark data, LLM/SAST logic or user files.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src/main"
APP = SRC / "java/com/analyzer/JavaFxApplication.java"
CTRL = SRC / "java/com/analyzer/ui/controller/MainController.java"
PAYLOAD = ROOT / "ui-v5-files/src/main"
TO_ADD = (
    "java/com/analyzer/ui/theme/UiPolishV5.java",
    "resources/styles/ui-v5-light.css",
    "resources/styles/ui-v5-dark.css",
)
APP_IMPORT_OLD = "import com.analyzer.ui.theme.UiContrastRepair;"
APP_IMPORT_NEW = "import com.analyzer.ui.theme.UiPolishV5;"
APP_CALL_OLD = "        UiContrastRepair.install(primaryStage, root);"
APP_CALL_NEW = "        UiPolishV5.install(primaryStage, root);"
# Remove just the damaged leading emoji on the known startup status message;
# do not replace any user messages or source content used by analysis.
WELCOME = re.compile(r'(appendMessageToChatHtml\("Система",\s*")[^"\r\n]*?(Загружен проект:\s*)')


def fail(reason: str) -> int:
    print("УСТАНОВКА ОСТАНОВЛЕНА: " + reason, file=sys.stderr)
    print("Проверьте содержимое проекта и предыдущие UI-патчи.", file=sys.stderr)
    return 1


def add_once(content: str, old: str, new: str, what: str) -> str:
    if content.count(new) == 1:
        return content
    if content.count(new) != 0 or content.count(old) != 1:
        raise ValueError(f"Не найдена однозначная точка вставки: {what}")
    return content.replace(old, old + "\n" + new, 1)


def main() -> int:
    try:
        if not (ROOT / "pom.xml").is_file():
            return fail("Распакуйте файлы ZIP в корень code-security-analyzer рядом с pom.xml")
        if not (APP.is_file() and CTRL.is_file()):
            return fail("Отсутствуют JavaFxApplication.java или MainController.java")
        for filename in ("UiAppearanceManager.java", "UiDashboardEnhancer.java",
                         "UiIconPolish.java", "UiContrastRepair.java"):
            if not (SRC / "java/com/analyzer/ui/theme" / filename).is_file():
                return fail("Сначала установите UI-патчи v1-v4: отсутствует " + filename)
        for name in TO_ADD:
            if not (PAYLOAD / name).is_file():
                return fail("Не найден файл обновления: " + name)

        app_old = APP.read_text(encoding="utf-8-sig")
        ctrl_old = CTRL.read_text(encoding="utf-8-sig")
        if app_old.count(APP_IMPORT_OLD) != 1 or app_old.count(APP_CALL_OLD) != 1:
            return fail("Отсутствует точка подключения UI Contrast Repair v4")
        if app_old.count(APP_IMPORT_NEW) != app_old.count(APP_CALL_NEW):
            return fail("Неполная предыдущая установка UI v5")
        app_new = add_once(app_old, APP_IMPORT_OLD, APP_IMPORT_NEW, "импорт UI v5")
        app_new = add_once(app_new, APP_CALL_OLD, APP_CALL_NEW, "вызов UI v5")

        matches = list(WELCOME.finditer(ctrl_old))
        if len(matches) != 1:
            return fail('В MainController не найдено единственное приветствие "Загружен проект"')
        match = matches[0]
        replacement = match.group(1) + match.group(2)
        ctrl_new = ctrl_old[:match.start()] + replacement + ctrl_old[match.end():]

        desired = {APP: app_new.encode("utf-8"), CTRL: ctrl_new.encode("utf-8")}
        for name in TO_ADD:
            destination = SRC / name
            content = (PAYLOAD / name).read_bytes()
            if destination.is_file() and destination.read_bytes() != content:
                return fail("Найдена изменённая версия файла: " + name + ". Перезапись запрещена")
            desired[destination] = content

        changes = [(dest, data) for dest, data in desired.items()
                   if not dest.is_file() or dest.read_bytes() != data]
        if not changes:
            print("UI Polish v5 уже установлен. Повторных изменений нет.")
            return 0

        backup = ROOT / "ui-theme-backup" / (
            datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-polish-v5")
        backup.mkdir(parents=True, exist_ok=False)
        try:
            for dest, _ in changes:
                if dest.exists():
                    oldCopy = backup / dest.relative_to(ROOT)
                    oldCopy.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(dest, oldCopy)
        except Exception as ex:
            shutil.rmtree(backup, ignore_errors=True)
            return fail("Не удалось создать резервные копии: " + str(ex))

        modified: list[Path] = []
        try:
            for dest, raw in changes:
                dest.parent.mkdir(parents=True, exist_ok=True)
                temp = dest.with_name(dest.name + ".ui-v5.tmp")
                temp.write_bytes(raw)
                os.replace(temp, dest)
                modified.append(dest)
                print("Обновлён: " + str(dest.relative_to(ROOT)))
        except Exception as ex:
            for dest in reversed(modified):
                saved = backup / dest.relative_to(ROOT)
                if saved.is_file():
                    shutil.copy2(saved, dest)
                else:
                    dest.unlink(missing_ok=True)
            return fail("Ошибка установки; выполнен откат: " + str(ex))

        print("Готово: UI Polish v5 установлен. Резервная копия: " + str(backup))
        print("Проверьте JDK 21, затем запустите .\\mvnw.cmd clean test")
        return 0
    except (OSError, UnicodeError, ValueError) as ex:
        return fail(str(ex))


if __name__ == "__main__":
    raise SystemExit(main())
