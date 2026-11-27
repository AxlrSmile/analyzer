Code Security Analyzer — WEB 1.0
================================

1. Закрой приложение JavaFX.
2. Распакуй все файлы ZIP в корень проекта, рядом с pom.xml.
3. Открой PowerShell в папке проекта.
4. Выполни:

   $env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot'
   $env:Path = "$env:JAVA_HOME\bin;$env:Path"
   .\.venv-semgrep\Scripts\python.exe .\apply_web_v1.py
   .\mvnw.cmd clean test

5. После BUILD SUCCESS запусти:

   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-web.ps1

6. Открой в браузере http://127.0.0.1:8080/

Полная документация: docs/WEB-1.0-RU.md (после установки).

Веб-прототип работает только на localhost. Не открывай доступ через интернет.
