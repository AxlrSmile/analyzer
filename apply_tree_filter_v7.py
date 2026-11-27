#!/usr/bin/env python3
"""UI v7 — recover filter panel from UI v5 without changing analyzer logic.

Targets only JavaFxApplication.java and UiPolishV5.java. UTF-8 without BOM.
Requires UI v5. Safe to rerun, with backups and best-effort rollback.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
APP = ROOT / 'src/main/java/com/analyzer/JavaFxApplication.java'
FILTER = ROOT / 'src/main/java/com/analyzer/ui/theme/UiPolishV5.java'
FXML = ROOT / 'src/main/resources/fxml/main-view.fxml'
IMPORT_ANCHOR = 'import com.analyzer.ui.theme.UiContrastRepair;'
IMPORT = 'import com.analyzer.ui.theme.UiPolishV5;'
CALL_ANCHOR = '        UiContrastRepair.install(primaryStage, root);'
CALL = '        UiPolishV5.install(primaryStage, root);'
MARK = '// UI Filter v7: look through intervening layout wrappers'
OLD_START = '''        Parent parent = fileTree.getParent();
        if (!(parent instanceof VBox column)) return;
'''
NEW_START = '''        // UI Filter v7: look through intervening layout wrappers
        Node slot = fileTree;
        Parent parent = fileTree.getParent();
        while (parent != null && !(parent instanceof VBox)) {
            slot = parent;
            parent = parent.getParent();
        }
        if (!(parent instanceof VBox column)) return;
'''
OLD_INDEX = '        int index = column.getChildren().indexOf(fileTree);'
NEW_INDEX = '        int index = column.getChildren().indexOf(slot);'
OLD_LATER = '        Platform.runLater(this::refreshCounter);'
NEW_LATER = '''        // A deferred retry handles skins/layout wrappers attached at first show.
        Platform.runLater(() -> {
            createFilterControls();
            refreshCounter();
        });'''


def fail(message: str) -> int:
    print('НЕ УСТАНОВЛЕНО: ' + message, file=sys.stderr)
    print('Файлы проекта не изменялись либо восстановлены из резервной копии.', file=sys.stderr)
    return 1


def patch_once(content: str, old: str, new: str, label: str) -> str:
    if new in content:
        return content
    if content.count(old) != 1:
        raise ValueError(label + ': требуется ровно одна точка изменения, найдено ' + str(content.count(old)))
    return content.replace(old, new, 1)


def main() -> int:
    try:
        if not (ROOT / 'pom.xml').is_file():
            return fail('Распакуйте ZIP рядом с pom.xml в корень code-security-analyzer')
        if not all(p.is_file() for p in (APP, FILTER, FXML)):
            return fail('Не найдены JavaFxApplication.java, UiPolishV5.java или main-view.fxml')
        fxml = FXML.read_text(encoding='utf-8-sig')
        if fxml.count('fx:id="fileTreeView"') != 1:
            return fail('В FXML нет единственного дерева fileTreeView; проверьте версию проекта')
        a0 = APP.read_text(encoding='utf-8-sig')
        f0 = FILTER.read_text(encoding='utf-8-sig')
        if (a0.count(IMPORT) > 1 or a0.count(CALL) > 1):
            return fail('Обнаружено несколько подключений UiPolishV5 — требуется ручная проверка')
        a1 = a0
        if IMPORT not in a1:
            a1 = patch_once(a1, IMPORT_ANCHOR, IMPORT_ANCHOR + '\n' + IMPORT,
                            'Подключение UiPolishV5 (import)')
        if CALL not in a1:
            a1 = patch_once(a1, CALL_ANCHOR, CALL_ANCHOR + '\n' + CALL,
                            'Запуск UiPolishV5')
        if a1.count(IMPORT) != 1 or a1.count(CALL) != 1:
            return fail('Неполная точка подключения UI v5')
        f1 = f0
        if MARK not in f1:
            f1 = patch_once(f1, OLD_START, NEW_START, 'Родитель дерева')
            f1 = patch_once(f1, OLD_INDEX, NEW_INDEX, 'Позиция панели фильтра')
            f1 = patch_once(f1, OLD_LATER, NEW_LATER, 'Отложенная настройка дерева')
        else:
            if NEW_START not in f1 or NEW_INDEX not in f1 or NEW_LATER not in f1:
                return fail('Ранее установлена неполная версия v7')
        # Ensure the filter is still dynamically created by Java; do not alter FXML.
        for required in ('new CheckBox("Только исходники")',
                         'createFilterControls();',
                         'search.setPromptText("Поиск файла или папки...")',
                         'fileTree.getRoot()'):
            if required not in f1:
                return fail('UiPolishV5 отличается от ожидаемого модуля: ' + required)
        changes = [(APP, a1.encode('utf-8')), (FILTER, f1.encode('utf-8'))]
        changes = [(path, contents) for path, contents in changes if path.read_bytes() != contents]
        if not changes:
            print('UI Filter v7 уже установлен; изменений не требуется.')
            return 0
        backup = ROOT / 'ui-theme-backup' / (datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '-filter-v7')
        backup.mkdir(parents=True, exist_ok=False)
        try:
            for target, _ in changes:
                stored = backup / target.relative_to(ROOT)
                stored.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, stored)
        except OSError as exc:
            shutil.rmtree(backup, ignore_errors=True)
            return fail('Не удалось создать резервную копию: ' + str(exc))
        modified = []
        try:
            for target, contents in changes:
                temp = target.with_name(target.name + '.filter-v7.tmp')
                temp.write_bytes(contents)
                os.replace(temp, target)
                modified.append(target)
                print('Обновлён: ' + str(target.relative_to(ROOT)))
        except OSError as exc:
            for target in reversed(modified):
                shutil.copy2(backup / target.relative_to(ROOT), target)
            return fail('Ошибка записи: ' + str(exc))
        print('Готово. Резервные копии: ' + str(backup))
        print('Проверка: найдите "UiPolishV5.install" в JavaFxApplication.java; фильтр появляется над деревом после запуска JavaFX.')
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        return fail(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
