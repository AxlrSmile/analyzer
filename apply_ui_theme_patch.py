#!/usr/bin/env python3
"""Apply the UI-only 9.0 RC1 appearance patch to a local project checkout."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "ui-theme-files" / "src" / "main"
DEST_DIR = ROOT / "src" / "main"
APPLICATION = DEST_DIR / "java" / "com" / "analyzer" / "JavaFxApplication.java"
IMPORT = "import com.analyzer.ui.theme.UiAppearanceManager;"
ANCHOR = "        primaryStage.setScene(new Scene(root));"
INSERT = "        UiAppearanceManager.install(primaryStage, root);"
FILES = (
    Path("java/com/analyzer/ui/theme/UiAppearanceManager.java"),
    Path("resources/styles/light-theme.css"),
    Path("resources/styles/dark-theme.css"),
)


def main() -> int:
    if not APPLICATION.exists() or not (ROOT / "pom.xml").exists():
        print("ОШИБКА: распакуйте ZIP в корень проекта рядом с pom.xml.", file=sys.stderr)
        return 1

    original = APPLICATION.read_text(encoding="utf-8-sig")
    already = IMPORT in original and INSERT in original
    if not already:
        if original.count("import com.analyzer.config.SpringFXMLLoader;") != 1:
            print("ОШИБКА: import SpringFXMLLoader отличается от ожидаемого — ничего не изменено.", file=sys.stderr)
            return 1
        if original.count(ANCHOR) != 1 or (IMPORT in original) != (INSERT in original):
            print("ОШИБКА: JavaFxApplication.java отличается от версии 9.0 RC1. Ничего не изменено.", file=sys.stderr)
            return 1
        patched = original.replace(
            "import com.analyzer.config.SpringFXMLLoader;",
            "import com.analyzer.config.SpringFXMLLoader;\n" + IMPORT,
            1,
        ).replace(ANCHOR, ANCHOR + "\n" + INSERT, 1)
    else:
        patched = original

    # Refuse to replace project-specific edits or an existing alternative theme.
    for relative in FILES:
        source = SOURCE_DIR / relative
        destination = DEST_DIR / relative
        if not source.is_file():
            print(f"ОШИБКА: отсутствует файл из архива: {source}", file=sys.stderr)
            return 1
        if destination.exists() and destination.read_bytes() != source.read_bytes():
            print(f"ОШИБКА: файл существует и отличается; не перезаписываем: {destination}", file=sys.stderr)
            return 1

    if not already:
        backup_dir = ROOT / "ui-theme-backup" / datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(APPLICATION, backup_dir / APPLICATION.name)
        # Java 21 rejects a BOM in a Java source: always write UTF-8 without BOM.
        APPLICATION.write_text(patched, encoding="utf-8", newline="\n")
        print(f"Создана резервная копия: {backup_dir / APPLICATION.name}")
    else:
        print("Точка подключения темы уже существует; повторно не добавляем.")

    for relative in FILES:
        source = SOURCE_DIR / relative
        destination = DEST_DIR / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
            print(f"Добавлен файл: {destination.relative_to(ROOT)}")
        else:
            print(f"Без изменений: {destination.relative_to(ROOT)}")
    print("Готово: тема и адаптивная раскладка установлены. Запустите Maven-тесты и приложение.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
