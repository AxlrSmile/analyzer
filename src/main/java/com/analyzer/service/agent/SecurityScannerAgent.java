package com.analyzer.service.agent;

import com.analyzer.domain.model.Vulnerability;
import com.analyzer.service.ai.OllamaClient;
import com.analyzer.service.parser.CodeChunk;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Первый агент аудита безопасности: запускает LLM-сканирование и проверяет
 * структуру результатов, прежде чем передать их интерфейсу.
 *
 * Результаты являются кандидатами на уязвимости, не подтвержденными находками.
 * Агент не исполняет исходный код и не изменяет файлы.
 */
@Service
public class SecurityScannerAgent {

    private static final Set<String> ALLOWED_SEVERITIES =
            Set.of("HIGH", "MEDIUM", "LOW");

    private final OllamaClient ollamaClient;
    private final ValidatorAgent validatorAgent;

    @Autowired
    public SecurityScannerAgent(OllamaClient ollamaClient, ValidatorAgent validatorAgent) {
        this.ollamaClient = ollamaClient;
        this.validatorAgent = validatorAgent;
    }

    // Сохраняем совместимость с тестами и кодом, создающими агент вручную.
    public SecurityScannerAgent(OllamaClient ollamaClient) {
        this(ollamaClient, new ValidatorAgent());
    }

    /**
     * @param codeChunk фрагмент исходного кода
     * @param language язык или имя исходного файла
     * @param modelName выбранная пользователем модель Ollama (может быть null)
     * @return непроверенные кандидатные находки; пустой список только для
     *         пустого ввода либо корректного пустого результата Ollama
     * @throws IllegalStateException если Ollama недоступна или выдала
     *         некорректный результат
     */
    public List<Vulnerability> scanChunk(String codeChunk, String language, String modelName) {
        if (codeChunk == null || codeChunk.isBlank()) return List.of();
        return validatorAgent.validateChunk(codeChunk, requestFindings(codeChunk, language, modelName));
    }

    /** Metadata-aware path used by UnifiedScanService for full-file coordinates. */
    public List<Vulnerability> scanLocatedChunk(CodeChunk chunk, String language, String modelName) {
        if (chunk == null) throw new IllegalArgumentException("Не передан фрагмент кода");
        return validatorAgent.validateLocatedChunk(
                chunk, requestFindings(chunk.prompt(), language, modelName));
    }

    private List<Vulnerability> requestFindings(String codeChunk, String language, String modelName) {
        // Патч OllamaClient №1 уже выбрасывает исключения при сбое Ollama.
        // Не превращаем исключение в «уязвимостей нет».
        List<Vulnerability> findings = ollamaClient.analyzeCodeChunk(
                codeChunk, language, modelName);
        if (findings == null) {
            throw new IllegalStateException("Ollama вернула null вместо списка уязвимостей");
        }

        for (int index = 0; index < findings.size(); index++) {
            Vulnerability finding = findings.get(index);
            if (finding == null || isBlank(finding.getTitle())
                    || isBlank(finding.getDescription())
                    || isBlank(finding.getRecommendation())) {
                throw new IllegalStateException(
                        "Неполная находка LLM №" + (index + 1) + ": отсутствуют обязательные поля");
            }

            String severity = finding.getSeverity();
            if (isBlank(severity)) {
                throw new IllegalStateException(
                        "Неполная находка LLM №" + (index + 1) + ": нет severity");
            }
            String normalized = severity.trim().toUpperCase(Locale.ROOT);
            if (!ALLOWED_SEVERITIES.contains(normalized)) {
                throw new IllegalStateException(
                        "Неизвестная severity в находке LLM №" + (index + 1)
                                + ": " + severity);
            }
            finding.setSeverity(normalized);
            // lineRange пока остается меткой LLM, а не проверенной координатой.
        }
        // Validation happens in the public entry point according to whether
        // metadata for the ORIGINAL file are available.
        return findings;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
