#!/usr/bin/env python3
"""Incremental UI + Semgrep location v6 for Code Security Analyzer 9.0 RC1.

Preflights all known anchors, creates backups, writes UTF-8 without BOM,
never changes Git metadata/benchmark data or source files under audit.
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'src/main'
FXML = SRC / 'resources/fxml/main-view.fxml'
DARK_CSS = SRC / 'resources/styles/ui-v5-dark.css'
LIGHT_CSS = SRC / 'resources/styles/ui-v5-light.css'
CTRL = SRC / 'java/com/analyzer/ui/controller/MainController.java'
SEMGREP = SRC / 'java/com/analyzer/service/sast/SemgrepCliService.java'
SEMGREP_TEST = ROOT / 'src/test/java/com/analyzer/service/sast/SemgrepExecutableResolutionTest.java'
PAYLOAD = ROOT / 'multilang-v6-files/src/test/java/com/analyzer/service/sast/SemgrepExecutableResolutionTest.java'

FXML_IMPORT = '<?import javafx.scene.layout.FlowPane?>'
FXML_SPLIT = '                        <SplitPane dividerPositions="0.28" focusTraversable="true" VBox.vgrow="ALWAYS">'
SCAN_SETTINGS = '''                        <!-- UI v6: user-selected local LLM for all supported source languages -->
                        <FlowPane fx:id="scanModelsBar" alignment="CENTER_LEFT" hgap="10.0" vgap="7.0" prefWrapLength="860.0" styleClass="csa-scan-models-bar">
                            <children>
                                <Label text="Модель для аудита:" styleClass="csa-scan-model-label" />
                                <ComboBox fx:id="scanModelComboBox" prefWidth="255.0" promptText="Модели Ollama..." />
                                <Button fx:id="refreshScanModelsButton" mnemonicParsing="false" text="Обновить модели" />
                                <Label text="Аудит: Java, Python, JS/TS, C/C++, Go, Rust, C#, Kotlin, PHP, Ruby, SQL и др.  |  Проверка исправлений javac: только Java" wrapText="true" maxWidth="660.0" styleClass="csa-scan-supported-languages" />
                            </children>
                        </FlowPane>
'''
CSS_MARK = '/* Scan Setup v6 */'
DARK_STYLES = """
/* Scan Setup v6 */
.csa-ui-v5 .csa-scan-models-bar {
    -fx-background-color: #233148;
    -fx-border-color: #34465f;
    -fx-border-width: 1;
    -fx-border-radius: 7;
    -fx-background-radius: 7;
    -fx-padding: 9 12;
}
.csa-ui-v5 .csa-scan-model-label {
    -fx-font-weight: bold;
    -fx-text-fill: #e8f0ff;
}
.csa-ui-v5 .csa-scan-supported-languages {
    -fx-text-fill: #aebfda;
    -fx-font-size: 11px;
}
"""
LIGHT_STYLES = """
/* Scan Setup v6 */
.csa-ui-v5 .csa-scan-models-bar {
    -fx-background-color: #eff5fc;
    -fx-border-color: #c8d4e5;
    -fx-border-width: 1;
    -fx-border-radius: 7;
    -fx-background-radius: 7;
    -fx-padding: 9 12;
}
.csa-ui-v5 .csa-scan-model-label {
    -fx-font-weight: bold;
    -fx-text-fill: #223952;
}
.csa-ui-v5 .csa-scan-supported-languages {
    -fx-text-fill: #506783;
    -fx-font-size: 11px;
}
"""

CTRL_FIELD = '    @FXML private ComboBox<String> scanModelComboBox;'
CTRL_BUTTON_FIELD = '    @FXML private Button refreshScanModelsButton;'
CTRL_INIT_ANCHOR = '        resetAgentLogHtml();\n        loadAvailableModels();'
CTRL_INIT_NEW = '''        resetAgentLogHtml();
        if (refreshScanModelsButton != null) {
            refreshScanModelsButton.setOnAction(event -> loadAvailableModels());
        }
        if (scanModelComboBox != null) {
            scanModelComboBox.valueProperty().addListener((obs, before, chosen) -> {
                if (chosen != null && !chosen.isBlank()) {
                    try {
                        java.util.prefs.Preferences.userNodeForPackage(MainController.class)
                                .put("scanModelSelected", chosen);
                    } catch (SecurityException | IllegalStateException ignored) {
                        // The selected model remains usable in this session.
                    }
                }
            });
        }
        loadAvailableModels();'''
CTRL_MODEL_OLD = '''                    scanModelComboBox.setItems(modelList);
                    scanModelComboBox.getSelectionModel().selectFirst();'''
CTRL_MODEL_NEW = '''                    String previouslySelected = scanModelComboBox.getValue();
                    String preferred = "";
                    try {
                        preferred = java.util.prefs.Preferences.userNodeForPackage(MainController.class)
                                .get("scanModelSelected", "");
                    } catch (SecurityException | IllegalStateException ignored) {
                        // Preferences are optional; model selection still works.
                    }
                    scanModelComboBox.setItems(modelList);
                    if (previouslySelected != null && models.contains(previouslySelected)) {
                        scanModelComboBox.setValue(previouslySelected);
                    } else if (models.contains(preferred)) {
                        scanModelComboBox.setValue(preferred);
                    } else if (models.contains("qwen2.5-coder:7b")) {
                        scanModelComboBox.setValue("qwen2.5-coder:7b");
                    } else {
                        scanModelComboBox.getSelectionModel().selectFirst();
                    }'''
CTRL_SCAN_OLD = '''        String targetModel = getSelectedScanModel();
        scannedFiles.clear();'''
CTRL_SCAN_NEW = '''        if (scanModelComboBox == null || scanModelComboBox.getValue() == null
                || scanModelComboBox.getValue().isBlank()) {
            new Alert(Alert.AlertType.WARNING,
                    "Сначала выберите модель Ollama на панели аудита. "+
                    "Для обновления списка используйте кнопку «Обновить модели».").showAndWait();
            return;
        }
        String targetModel = getSelectedScanModel();
        scannedFiles.clear();'''

SEMGREP_CALL1_OLD = 'return scanWithExecutable(root, selectedFiles, findExecutable(root));'
SEMGREP_CALL1_NEW = 'return scanWithExecutable(root, selectedFiles, findExecutable());'
SEMGREP_CALL2_OLD = 'Path executable = findExecutable(trustedRoot);'
SEMGREP_CALL2_NEW = 'Path executable = findExecutable();'
SEMGREP_METHOD_OLD = '''    private static Path findExecutable(Path root) {
        String override = System.getProperty("analyzer.semgrep.executable", "").trim();
        if (!override.isEmpty()) return Path.of(override);
        for (String location : List.of(".venv-semgrep/Scripts/semgrep.exe", ".venv-semgrep/bin/semgrep")) {
            Path local = root.resolve(location);
            if (Files.isRegularFile(local)) return local.toAbsolutePath();
        }
        // Fall back to PATH; process errors are explicitly reported, never treated as zero findings.
        return Path.of("semgrep");
    }'''
SEMGREP_METHOD_NEW = '''    /**
     * The selected project is source data, not a trusted executable directory.
     * Find Semgrep beside the ANALYZER, not inside a project being audited.
     */
    private static Path findExecutable() {
        String override = System.getProperty("analyzer.semgrep.executable", "").trim();
        String configuredHome = System.getProperty("analyzer.home", "").trim();
        String home = configuredHome.isBlank()
                ? System.getProperty("user.dir", ".") : configuredHome;
        return locateExecutable(Path.of(home), override);
    }

    /** Package-private pure resolver for isolated regression tests. */
    static Path locateExecutable(Path trustedAnalyzerHome, String configuredExecutable) {
        if (configuredExecutable != null && !configuredExecutable.isBlank()) {
            return Path.of(configuredExecutable.trim());
        }
        Path home = trustedAnalyzerHome.toAbsolutePath().normalize();
        for (String location : List.of(".venv-semgrep/Scripts/semgrep.exe", ".venv-semgrep/bin/semgrep")) {
            Path local = home.resolve(location);
            if (Files.isRegularFile(local)) return local.toAbsolutePath();
        }
        // PATH is a trusted OS/developer configuration; scanner startup failures
        // are reported explicitly, never converted to zero security findings.
        return Path.of("semgrep");
    }'''


def err(msg: str) -> int:
    print('УСТАНОВКА ОСТАНОВЛЕНА: ' + msg, file=sys.stderr)
    print('Рабочие файлы не удалялись; при ошибке записи выполнен откат.', file=sys.stderr)
    return 1


def exactly_once_patch(source: str, old: str, new: str, tag: str) -> str:
    if old == new:
        raise ValueError('Internal patch error: '+tag)
    if new in source:
        return source
    n = source.count(old)
    if n != 1:
        raise ValueError(f'{tag}: ожидается один исходный фрагмент, обнаружено {n}')
    return source.replace(old,new,1)


def transform_fxml(original: str) -> str:
    current = original
    if 'fx:id="scanModelsBar"' not in current:
        if current.count(FXML_SPLIT) != 1:
            raise ValueError('FXML: не найдена единственная панель анализа (SplitPane)')
        current = current.replace(FXML_SPLIT, SCAN_SETTINGS + '\n' + FXML_SPLIT, 1)
    if current.count('fx:id="scanModelComboBox"') != 1:
        raise ValueError('FXML: требуется ровно один scanModelComboBox')
    if current.count('fx:id="refreshScanModelsButton"') != 1:
        raise ValueError('FXML: требуется ровно один refreshScanModelsButton')
    if FXML_IMPORT not in current:
        current = exactly_once_patch(current,
            '<?import javafx.scene.layout.HBox?>',
            '<?import javafx.scene.layout.HBox?>\n' + FXML_IMPORT,'FXML: импорт FlowPane')
    # Do not reformat FXML: exact text is preserved except the inserted block.
    ET.fromstring(current.encode('utf-8'))
    return current


def transform_controller(original: str) -> str:
    current = exactly_once_patch(original, CTRL_FIELD, CTRL_FIELD+'\n'+CTRL_BUTTON_FIELD,
                                 'MainController: модель и кнопка обновления')
    current = exactly_once_patch(current, CTRL_INIT_ANCHOR, CTRL_INIT_NEW,
                                 'MainController: выбор модели и сохранение')
    current = exactly_once_patch(current, CTRL_MODEL_OLD, CTRL_MODEL_NEW,
                                 'MainController: восстановление выбора')
    current = exactly_once_patch(current, CTRL_SCAN_OLD, CTRL_SCAN_NEW,
                                 'MainController: запрет запуска без выбора')
    return current


def transform_semgrep(original: str) -> str:
    current = exactly_once_patch(original, SEMGREP_CALL1_OLD, SEMGREP_CALL1_NEW,
                                 'Semgrep: основной вызов')
    current = exactly_once_patch(current, SEMGREP_CALL2_OLD, SEMGREP_CALL2_NEW,
                                 'Semgrep: повторная проверка исправления')
    current = exactly_once_patch(current, SEMGREP_METHOD_OLD, SEMGREP_METHOD_NEW,
                                 'Semgrep: доверенная папка приложения')
    return current


def main() -> int:
    try:
        if not (ROOT/'pom.xml').is_file():
            return err('Распакуйте v6 в корень code-security-analyzer рядом с pom.xml')
        for path in (FXML, CTRL, SEMGREP, DARK_CSS, LIGHT_CSS, PAYLOAD):
            if not path.is_file(): return err(f'Нет требуемого файла: {path.relative_to(ROOT)}')
        prior = SRC/'java/com/analyzer/ui/theme/UiPolishV5.java'
        if not prior.is_file():
            return err('Сначала установите UI v5: не найден UiPolishV5.java')
        fxml_old = FXML.read_text(encoding='utf-8-sig')
        ctrl_old = CTRL.read_text(encoding='utf-8-sig')
        sast_old = SEMGREP.read_text(encoding='utf-8-sig')
        changes = {
            FXML: transform_fxml(fxml_old).encode('utf-8'),
            CTRL: transform_controller(ctrl_old).encode('utf-8'),
            SEMGREP: transform_semgrep(sast_old).encode('utf-8'),
        }
        for stylesheet, addition in ((DARK_CSS, DARK_STYLES),(LIGHT_CSS, LIGHT_STYLES)):
            current = stylesheet.read_text(encoding='utf-8-sig')
            if current.count(CSS_MARK) > 1:
                return err('В CSS несколько блоков v6: '+str(stylesheet))
            if CSS_MARK not in current:
                current = current.rstrip() + '\n\n' + addition.strip() + '\n'
            changes[stylesheet] = current.encode('utf-8')
        test_bytes = PAYLOAD.read_bytes()
        if SEMGREP_TEST.exists() and SEMGREP_TEST.read_bytes() != test_bytes:
            return err('Существует изменённая версия SemgrepExecutableResolutionTest.java; не перезаписываем')
        changes[SEMGREP_TEST] = test_bytes
        planned = [(p, content) for p,content in changes.items()
                   if not p.exists() or p.read_bytes() != content]
        if not planned:
            print('UI + Multi-language Scan v6 уже установлены; повторных изменений нет.')
            return 0
        backup = ROOT/'ui-theme-backup'/(datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'-scan-v6')
        backup.mkdir(parents=True,exist_ok=False)
        for p,_ in planned:
            if p.exists():
                oldcopy = backup/p.relative_to(ROOT)
                oldcopy.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(p,oldcopy)
        done=[]
        try:
            for p, content in planned:
                p.parent.mkdir(parents=True, exist_ok=True)
                temp = p.with_name(p.name+'.scan-v6.tmp')
                temp.write_bytes(content)
                os.replace(temp,p)
                done.append(p)
                print('Обновлено: '+str(p.relative_to(ROOT)))
        except Exception as exc:
            for p in reversed(done):
                oldcopy=backup/p.relative_to(ROOT)
                if oldcopy.is_file(): shutil.copy2(oldcopy,p)
                else: p.unlink(missing_ok=True)
            return err('Ошибка записи: '+str(exc))
        print('Готово. Резервные копии: '+str(backup))
        print('Проверьте JDK 21, Maven и работу с файлом .py/.js/.go вне папки анализатора.')
        return 0
    except (OSError,UnicodeError,ValueError,ET.ParseError) as exc:
        return err(str(exc))

if __name__=='__main__':
    raise SystemExit(main())
