#!/usr/bin/env python3
"""Additive browser UI patch. Designed for the JavaFX repo with installed UI v1-v8.

Does not touch the desktop controller, UI CSS, test datasets, or any user code.
"""
from pathlib import Path
from datetime import datetime
import shutil
import sys

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "web-v1-files"
MAIN = ROOT / "src/main/java/com/analyzer/CodeSecurityAnalyzerApplication.java"
FX = ROOT / "src/main/java/com/analyzer/JavaFxApplication.java"
POM = ROOT / "pom.xml"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked_patch(main_text, fx_text, pom_text):
    require((PAYLOAD / "src/main/java/com/analyzerweb/WebServerApplication.java").exists(),
            "Нет файлов Web 1.0. Распакуйте ZIP полностью.")
    if 'com.analyzerweb.WebServerApplication.start(webArgs)' not in main_text:
        needle = 'Application.launch(JavaFxApplication.class, args);'
        require(main_text.count(needle) == 1, "Не удалось определить точку входа JavaFX; исходник не изменён")
        insertion = '''if (java.util.Arrays.asList(args).contains("--web")) {
            String[] webArgs = java.util.Arrays.stream(args)
                    .filter(arg -> !"--web".equals(arg))
                    .toArray(String[]::new);
            com.analyzerweb.WebServerApplication.start(webArgs);
            return;
        }
        Application.launch(JavaFxApplication.class, args);'''
        main_text = main_text.replace(needle, insertion, 1)
    if 'org.springframework.boot.WebApplicationType.NONE' not in fx_text:
        needle = '.sources(CodeSecurityAnalyzerApplication.class)'
        require(fx_text.count(needle) == 1, "Не удалось определить запуск Spring в JavaFX; исходник не изменён")
        fx_text = fx_text.replace(needle, needle + '\n                .web(org.springframework.boot.WebApplicationType.NONE)', 1)
    if '<artifactId>spring-boot-starter-webmvc</artifactId>' not in pom_text:
        needle = '<dependencies>'
        require(pom_text.count(needle) == 1, "В pom.xml не найден раздел dependencies; исходник не изменён")
        pom_text = pom_text.replace(needle, needle + '''
        <!-- Local browser interface; desktop still uses JavaFX -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc</artifactId>
        </dependency>''', 1)
    return {MAIN: main_text, FX: fx_text, POM: pom_text}


def main():
    for p in (MAIN, FX, POM):
        require(p.is_file(), f"Не найден: {p.relative_to(ROOT)}. Запустите из корня code-security-analyzer.")
    source_paths = [p for p in PAYLOAD.rglob("*") if p.is_file()]
    require(source_paths and (PAYLOAD / 'src/main/resources/static/index.html').is_file(),
            "Неполный архив: отсутствуют файлы веб-интерфейса")
    # Detect conflicts before changing anything (including the pom or entry points).
    updates = checked_patch(*(p.read_text(encoding='utf-8-sig') for p in (MAIN, FX, POM)))
    for source in source_paths:
        destination = ROOT / source.relative_to(PAYLOAD)
        if destination.exists():
            require(destination.is_file() and destination.read_bytes() == source.read_bytes(),
                    f"КОНФЛИКТ: {destination.relative_to(ROOT)} отличается от патча. Ничего не изменено.")
    to_change = {p: content for p, content in updates.items()
                 if p.read_text(encoding='utf-8-sig') != content}
    if not to_change and all((ROOT / p.relative_to(PAYLOAD)).is_file() for p in source_paths):
        print('Web 1.0 уже установлен. Изменений нет.')
        return
    backup = ROOT / 'web-v1-backup' / datetime.now().strftime('%Y%m%d-%H%M%S')
    for p in to_change:
        copy = backup / p.relative_to(ROOT)
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, copy)
    if to_change:
        print(f"Резервная копия исходников: {backup}")
    for source in source_paths:
        target = ROOT / source.relative_to(PAYLOAD)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            print(f"Добавлен: {target.relative_to(ROOT)}")
    for target, content in to_change.items():
        # Always UTF-8 without BOM (critical for Java source and Cyrillic strings).
        original_bytes = target.read_bytes()
        line_end = '\r\n' if b'\r\n' in original_bytes else '\n'
        target.write_text(content, encoding='utf-8', newline=line_end)
        print(f"Обновлён: {target.relative_to(ROOT)}")
    print('Web 1.0 установлен. JDK 21: .\\mvnw.cmd clean test ; затем .\\run-web.ps1')


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        print('ОСТАНОВЛЕНО: ' + str(ex), file=sys.stderr)
        sys.exit(1)
