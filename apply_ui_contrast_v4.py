#!/usr/bin/env python3
"""Apply exact-match UI-only correction to Code Security Analyzer v3.

Safety: validates all preconditions before writing, backs up each changed file,
rolls back on failure, refuses conflicting modifications, preserves UTF-8 without BOM.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / 'src/main/java/com/analyzer'
APP = JAVA / 'JavaFxApplication.java'
CONTROLLER = JAVA / 'ui/controller/MainController.java'
TARGET = JAVA / 'ui/theme/UiContrastRepair.java'
PAYLOAD = ROOT / 'ui-v4-files/src/main/java/com/analyzer/ui/theme/UiContrastRepair.java'

APP_IMPORT = 'import com.analyzer.ui.theme.UiIconPolish;'
APP_CALL = '        UiIconPolish.install(primaryStage, root);'
NEW_IMPORT = 'import com.analyzer.ui.theme.UiContrastRepair;'
NEW_CALL = '        UiContrastRepair.install(primaryStage, root);'
OLD_TREE = 'setStyle("-fx-text-fill: #2c3e50;");'
NEW_TREE = 'setStyle(""); // UI v4: allow dark/light theme to style tree text'
OLD_HTML = 'String content = htmlBuffer.toString() + "</body></html>";'
NEW_HTML = ('String content = com.analyzer.ui.theme.UiContrastRepair.webHtml('
            'webView, htmlBuffer.toString()) + "</body></html>";')


def reject(message: str) -> int:
    print('УСТАНОВКА ОСТАНОВЛЕНА: ' + message, file=sys.stderr)
    print('Проверьте исходные файлы, ничего не удаляйте.', file=sys.stderr)
    return 1


def patch_once(content: str, old: str, new: str, label: str) -> str:
    old_count, new_count = content.count(old), content.count(new)
    if new_count == 1:
        return content
    if old_count != 1 or new_count != 0:
        raise ValueError(f'{label}: ожидается одна исходная строка или уже установленное изменение')
    return content.replace(old, new, 1)


def main() -> int:
    try:
        if not (ROOT / 'pom.xml').is_file():
            return reject('Сначала распакуйте архив в корень проекта рядом с pom.xml')
        if not (APP.is_file() and CONTROLLER.is_file() and PAYLOAD.is_file()):
            return reject('Отсутствуют JavaFxApplication, MainController или файл патча')
        for required in ('UiAppearanceManager.java', 'UiDashboardEnhancer.java', 'UiIconPolish.java'):
            if not (JAVA / 'ui/theme' / required).is_file():
                return reject('Сначала установите предыдущие UI-патчи: отсутствует ' + required)

        app = APP.read_text(encoding='utf-8-sig')
        ctrl = CONTROLLER.read_text(encoding='utf-8-sig')
        if app.count(APP_IMPORT) != 1 or app.count(APP_CALL) != 1:
            return reject('Не найдена уникальная точка подключения UI Icons v3')
        app = patch_once(app, APP_IMPORT, APP_IMPORT + '\n' + NEW_IMPORT, 'Импорт')
        app = patch_once(app, APP_CALL, APP_CALL + '\n' + NEW_CALL, 'Инициализация')
        ctrl = patch_once(ctrl, OLD_TREE, NEW_TREE, 'Контраст дерева')
        ctrl = patch_once(ctrl, OLD_HTML, NEW_HTML, 'Цвета HTML-чата')

        if TARGET.is_file() and TARGET.read_bytes() != PAYLOAD.read_bytes():
            return reject('UiContrastRepair.java уже изменён: автоматическая перезапись запрещена')
        desired = {
            APP: app.encode('utf-8'),
            CONTROLLER: ctrl.encode('utf-8'),
            TARGET: PAYLOAD.read_bytes(),
        }
        changes = [(dest, raw) for dest, raw in desired.items()
                   if not dest.is_file() or dest.read_bytes() != raw]
        if not changes:
            print('UI Contrast Repair v4 уже установлен, файлы не изменены.')
            return 0

        backup = ROOT / 'ui-theme-backup' / (datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '-contrast-v4')
        backup.mkdir(parents=True, exist_ok=False)
        try:
            for dest, _ in changes:
                if dest.exists():
                    copy_to = backup / dest.relative_to(ROOT)
                    copy_to.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(dest, copy_to)
        except Exception:
            shutil.rmtree(backup, ignore_errors=True)
            return reject('Не удалось создать резервные копии')
        modified = []
        try:
            for dest, raw in changes:
                dest.parent.mkdir(parents=True, exist_ok=True)
                temp = dest.with_name(dest.name + '.ui-v4.tmp')
                temp.write_bytes(raw)
                os.replace(temp, dest)
                modified.append(dest)
                print('Обновлён: ' + str(dest.relative_to(ROOT)))
        except Exception as exc:
            for dest in reversed(modified):
                old = backup / dest.relative_to(ROOT)
                if old.is_file():
                    shutil.copy2(old, dest)
                else:
                    dest.unlink(missing_ok=True)
            return reject('Ошибка установки с откатом: ' + str(exc))
        print('Готово: UI Contrast Repair v4. Резервные копии: ' + str(backup))
        print('Следующий шаг: JDK 21 и .\\mvnw.cmd clean test')
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        return reject(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
