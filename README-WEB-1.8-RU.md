# Code Security Analyzer — Web 1.8 / Fix & Validation

## Назначение
Патч к **точной Web 1.7**, не самостоятельная программа.
Обновление **не удаляет сигналы LLM**, не переписывает исходники, не меняет JavaFX и не записывает код в историю.

### Изменения
- 04 / Fix: предварительный triage с предупреждением о возможном False Positive. Находки, помеченные как POSSIBLE_FP (например, Case011 с PreparedStatement), требуют осознанного подтверждения перед созданием черновика исправления. Гейт — только браузерная UX-защита, не граница безопасности сервера.
- Java API: поле `assessment` в ответе `/api/fix-preview` со статусами NO_CHANGE / NOT_VALIDATED / API_UNVERIFIED / SAST_NOT_CHECKED / STATIC_REGRESSION / STATIC_SIGNALS_REDUCED / STATIC_SIGNALS_UNCHANGED. Все статусы требуют ручной проверки; уменьшение Semgrep не доказательство безопасности.
- Web: пояснение к результатам Java/API/Semgrep и экспорт **metadata-only** протокола проверки, без source/proposed/diff/validationDetails.
- Офлайн `benchmark-dataset/evaluate_web_v18.py`: файловые Precision/Recall/F1 на базе `ground_truth.json`. При неполном анализе результат исключается из матрицы, а не считается отсутствием уязвимости. Для определённости рекомендуется экспорт по одному Java-файлу на каждый запуск. `--origin LLM` или `--origin Semgrep`.
- Проверки: Java JUnit, Node и Python.

## Установка
1. Остановите сервер Web (Ctrl+C). Создайте копию проекта и экспортируйте нужные истории из браузера.
2. Распакуйте ZIP **в корень проекта**, рядом с `pom.xml`. Не распаковывайте в `src`.
3. В PowerShell из корня:

```powershell
.\.venv-semgrep\Scripts\python.exe .\apply_web_v18.py
```

Если .venv-semgrep не содержит python, используйте `py -3 .\apply_web_v18.py`.
Установщик проверяет SHA-256 исходных файлов Web 1.7 и файлов архива, создаёт резервные копии в `web-v18-backup` и не перезаписывает локальные несовпадающие файлы. При ошибке `ОСТАНОВЛЕНО` не форсируйте установку.

4. Убедитесь, что Maven использует Java 21:

```powershell
$javac = (Get-Command javac.exe).Source
$jdk21 = Split-Path (Split-Path $javac -Parent) -Parent
$env:JAVA_HOME = $jdk21
$env:Path = "$jdk21\bin;$env:Path"
.\mvnw.cmd -version
.\mvnw.cmd clean test
```

5. После BUILD SUCCESS запустите `powershell -NoProfile -ExecutionPolicy Bypass -File .\run-web.ps1`, откройте `http://127.0.0.1:8080` и нажмите Ctrl+F5.

## Ручной тест
1. Case011.java + mistral:7b → выберите ложный SQL-сигнал; увидите предупреждение о возможном FP. Кнопка генерации должна требовать ручного подтверждения. После подтверждения можно получить только черновик.
2. Case008.java + любая доступная LLM → выберите SQL-сигнал. Обязательное подтверждение требуется только при потенциальном FP; иначе генерация работает как прежде.
3. После генерации проверьте Java/API, Semgrep до/после, вывод assessment; экспортируйте протокол JSON и проверьте отсутствие исходного кода.
4. Для работы с точностью сохраните по одному Web JSON-отчёту на каждый case. **Не смешивайте разные версии и модели** в одном эксперименте.

Пример оценки из корня проекта:
```powershell
py -3 .\benchmark-dataset\evaluate_web_v18.py --origin LLM --out metrics.json .\reports\Case*.json
```

**Ограничения:** проверка SQL-параметризации эвристическая и может пропускать сложные случаи. Даже `PASSED` и `COMPLETE` не означают безопасный код. Для реальной оценки Precision/Recall/F1 требуется полный и одинаковый корпус и ручная верификация эталона. Полный Maven и живую Ollama на вашей машине нужно проверить после установки.
