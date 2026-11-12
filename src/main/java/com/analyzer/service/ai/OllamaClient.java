package com.analyzer.service.ai;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class OllamaClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String ollamaUrl;
    private final String defaultModel;

    public static class ChatMessage {
        private String role;
        private String content;

        public ChatMessage() {}

        public ChatMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }

        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }

    public OllamaClient(
            ObjectMapper objectMapper,
            @Value("${ollama.url:http://localhost:11434}") String ollamaUrl,
            @Value("${ollama.model:qwen2.5-coder:7b}") String defaultModel) {

        this.objectMapper = objectMapper;
        this.ollamaUrl = ollamaUrl;
        this.defaultModel = defaultModel;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(60))
                .build();
    }

    public List<String> getAvailableModels() {
        List<String> models = new ArrayList<>();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ollamaUrl + "/api/tags"))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode modelsNode = root.get("models");
                if (modelsNode != null && modelsNode.isArray()) {
                    for (JsonNode modelNode : modelsNode) {
                        models.add(modelNode.get("name").asText());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Не удалось получить список моделей Ollama: " + e.getMessage());
        }

        if (models.isEmpty()) {
            models.add(defaultModel);
        }
        return models;
    }

    public String chatWithModel(String modelName, String prompt) {
        String targetModel = (modelName != null && !modelName.isBlank()) ? modelName : defaultModel;

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("model", targetModel);
        requestBody.put("prompt", prompt);
        requestBody.put("stream", false);

        try {
            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ollamaUrl + "/api/generate"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofSeconds(180))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode responseNode = objectMapper.readTree(response.body());
                return responseNode.get("response").asText();
            } else {
                throw new RuntimeException("Ошибка Ollama API: HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при вызове Ollama: " + e.getMessage(), e);
        }
    }

    public String chatWithHistory(String modelName, List<ChatMessage> history) {
        String targetModel = (modelName != null && !modelName.isBlank()) ? modelName : defaultModel;

        List<Map<String, String>> messages = new ArrayList<>();
        for (ChatMessage msg : history) {
            messages.add(Map.of("role", msg.getRole(), "content", msg.getContent()));
        }

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("model", targetModel);
        requestBody.put("messages", messages);
        requestBody.put("stream", false);

        try {
            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ollamaUrl + "/api/chat"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofSeconds(180))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                return root.get("message").get("content").asText();
            } else {
                throw new RuntimeException("Ошибка Ollama Chat API: HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка чата Ollama: " + e.getMessage(), e);
        }
    }

    /**
     * Анализ чанка кода с автоматическим определением языка (перегрузка для обратной совместимости)
     */
    public List<Vulnerability> analyzeCodeChunk(String codeChunk, String language) {
        return analyzeCodeChunk(codeChunk, language, defaultModel);
    }

    /**
     * Полноценный мультиязычный анализ чанка кода (C/C++, Python, JS, Java, Go и др.)
     */
    /**
     * Анализ фрагмента кода с указанием модели
     */
    public List<Vulnerability> analyzeCodeChunk(String codeChunk, String language, String modelName) {
        String targetModel = (modelName != null && !modelName.isBlank()) ? modelName : defaultModel;

        String langContext = (language != null && !language.equalsIgnoreCase("Unknown"))
                ? "Язык фрагмента: " + language + "."
                : "Определи язык программирования переданного фрагмента автоматически.";

        String prompt = """
            Ты проводишь предварительный статический аудит безопасности кода.
            %s
            Возвращай только JSON-объект с массивом vulnerabilities.
            Для КАЖДОЙ находки обязательны: title, severity (HIGH/MEDIUM/LOW),
            cwe (существующий идентификатор вида CWE-89), startLine и endLine (ЦЕЛЫЕ
            числовые АБСОЛЮТНЫЕ номера строк файла), evidence, description, recommendation.
            evidence = ДОСЛОВНАЯ цитата одной строки исходного кода внутри диапазона
            startLine..endLine (минимум 6 символов), без маркировки Lномер | и без многоточий.
            Категория CWE выбирается по РЕАЛЬНОМУ МЕХАНИЗМУ В КОДЕ, а не по общей тревожности.
            Используй справочник: SQL-инъекция CWE-89; системные команды через shell CWE-78;
            Path Traversal CWE-22; XSS CWE-79; XXE CWE-611; десериализация Java-объектов CWE-502;
            записанные в исходном коде секреты CWE-798; секреты в журналах CWE-532;
            SSRF CWE-918; слабая случайность для защитных токенов CWE-338.
            CWE-89 относится ТОЛЬКО к SQL: не выбирай CWE-89 для логирования, файлов,
            HTTP/URI, ProcessBuilder, XML, HTML, ObjectInputStream или секретов.
            Наличие API само по себе не делает код уязвимым: проверяй PreparedStatement,
            HTML-экранирование, ограничения XML-сущностей, канонизацию пути,
            отдельные аргументы ProcessBuilder без командной оболочки.
            Не используй примеры в этой инструкции в качестве доказательств находок.
            Нельзя выдумывать номера строк, код CWE или доказательства. Считай только
            строки исходного кода Lномер |; служебные заголовки и текст запроса не являются
            строками исходного файла. Если нет достаточно подтверждений — не создавай находку.
            Не считай отсутствие уязвимости доказательством безопасности.
            Без находок: {"vulnerabilities": []}.

            Код для анализа (Lномер | обозначает оригинальную строку файла):
            ```
            %s
            ```
            """.formatted(langContext, withSourceLineNumbers(codeChunk));

        Map<String, Object> property = Map.of(
                "title", Map.of("type", "string"),
                "severity", Map.of("type", "string", "enum", List.of("HIGH", "MEDIUM", "LOW")),
                "cwe", Map.of("type", "string"),
                "startLine", Map.of("type", "integer"),
                "endLine", Map.of("type", "integer"),
                "evidence", Map.of("type", "string"),
                "description", Map.of("type", "string"),
                "recommendation", Map.of("type", "string"));
        Map<String, Object> itemSchema = Map.of(
                "type", "object", "properties", property,
                "required", List.of("title", "severity", "cwe", "startLine", "endLine",
                        "evidence", "description", "recommendation"),
                "additionalProperties", false);
        Map<String, Object> outputSchema = Map.of(
                "type", "object",
                "properties", Map.of("vulnerabilities", Map.of("type", "array", "items", itemSchema)),
                "required", List.of("vulnerabilities"), "additionalProperties", false);
        StructuredFindingParser parser = new StructuredFindingParser(objectMapper);
        String numberedSource = withSourceLineNumbers(codeChunk);
        String lastValidationFailure = "";
        int firstAttemptCandidateCount = 0;
        List<String> invalidResponses = new ArrayList<>();
        // Retry only an invalid model response, never an HTTP/network failure.
        // A second invalid response fails the file and is recorded in scan diagnostics.
        for (int attempt = 0; attempt < 2; attempt++) {
            String currentPrompt = attempt == 0 ? prompt : prompt + "\n\n"
                    + "ПОВТОРНЫЙ ЗАПРОС: предыдущий ответ не прошёл проверку: "
                    + lastValidationFailure + ". Исправь формат, координаты и evidence. "
                    + "Цитируй РОВНО ОДНУ реальную строку с правильным L-номером. "
                    + "Сохрани обоснованные находки, не заменяй их пустым списком. Верни только JSON.";
            Map<String, Object> requestBody = Map.of(
                    "model", targetModel,
                    "prompt", currentPrompt,
                    "stream", false,
                    "format", outputSchema,
                    "options", Map.of("temperature", 0));
            String rawResult;
            try {
                String jsonPayload = objectMapper.writeValueAsString(requestBody);
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(ollamaUrl + "/api/generate"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                        .timeout(Duration.ofSeconds(360))
                        .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IllegalStateException("Ollama API вернул HTTP " + response.statusCode());
                }
                JsonNode apiJson = objectMapper.readTree(response.body());
                JsonNode answer = apiJson == null ? null : apiJson.get("response");
                if (answer == null || !answer.isTextual() || answer.asText().isBlank()) {
                    throw new IllegalStateException("Ollama вернула пустое или некорректное поле response");
                }
                rawResult = answer.asText();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Анализ кода прерван (модель: " + targetModel + ")", e);
            } catch (Exception e) {
                throw new IllegalStateException("Анализ кода не выполнен (модель: " + targetModel
                        + "): " + e.getMessage(), e);
            }
            try {
                List<Vulnerability> result = parser.parse(rawResult);
                if (attempt > 0 && result.size() < firstAttemptCandidateCount) {
                    throw new IllegalArgumentException("повторный ответ потерял ранее найденные кандидаты: "
                            + firstAttemptCandidateCount + " -> " + result.size());
                }
                StructuredEvidencePreflight.check(numberedSource, result);
                for (Vulnerability finding : result) finding.setModelOutputStatus("EVIDENCE_MATCHED");
                return result;
            } catch (java.io.IOException | IllegalArgumentException validationFailure) {
                if (attempt == 0) {
                    firstAttemptCandidateCount = responseCandidateCount(rawResult);
                }
                invalidResponses.add(rawResult);
                lastValidationFailure = conciseValidationError(validationFailure.getMessage());
            }
        }
        // Both strict attempts failed. Retain independently parseable candidates,
        // but NEVER turn a malformed response into a successful clean scan.
        StructuredFindingParser.ParseOutcome best = null;
        for (String raw : invalidResponses) {
            try {
                var current = parser.parseBestEffort(raw);
                if (!current.findings().isEmpty() && (best == null
                        || current.findings().size() > best.findings().size()
                        || (current.findings().size() == best.findings().size()
                        && current.issues().size() < best.issues().size()))) {
                    best = current;
                }
            } catch (java.io.IOException | IllegalArgumentException ignored) {
                // A malformed JSON root must not be converted into a clean response.
            }
        }
        if (best != null) {
            for (Vulnerability finding : best.findings()) {
                boolean evidenceMatches = StructuredEvidencePreflight.matches(numberedSource, finding);
                boolean uncertainEvidence = !evidenceMatches
                        || "EVIDENCE_UNVERIFIED".equals(finding.getModelOutputStatus());
                if (uncertainEvidence) {
                    finding.setModelOutputStatus("EVIDENCE_UNVERIFIED");
                    finding.setModelOutputNote("После двух попыток цитата LLM не подтверждена оригиналом. "
                            + "Находка сохранена только для ручного анализа.");
                    // Original source context is separate from quoted model evidence.
                    finding.setSourceExcerpt(StructuredEvidencePreflight.sourceExcerpt(
                            numberedSource, finding.getStartLine()));
                } else {
                    finding.setModelOutputStatus("EVIDENCE_MATCHED");
                }
                if (best.candidateCount() > best.findings().size()
                        || firstAttemptCandidateCount > best.candidateCount()) {
                    finding.setModelOutputStatus("PARTIAL_RESPONSE");
                    finding.setModelOutputNote("Часть исходных кандидатов отсутствует или имеет "
                            + "некорректную структуру; анализ неполный. "
                            + (uncertainEvidence ? "Цитата также не подтверждена." : ""));
                }
            }
            return best.findings();
        }
        throw new IllegalStateException("LLM-анализ неполный (модель: " + targetModel
                + "): нет пригодных кандидатов после двух попыток: " + lastValidationFailure);
    }

    private int responseCandidateCount(String response) {
        try {
            JsonNode root = objectMapper.readTree(response);
            JsonNode findings = root == null ? null : root.path("vulnerabilities");
            return findings != null && findings.isArray() ? findings.size() : 0;
        } catch (Exception ignored) {
            return 0;
        }
    }

    private static String conciseValidationError(String message) {
        if (message == null) return "некорректный ответ";
        String compact = message.replaceAll("[\r\n\t]", " ");
        return compact.length() > 160 ? compact.substring(0, 160) : compact;
    }

    private static String withSourceLineNumbers(String codeChunk) {
        // Long CodeChunks already contain absolute L-numbers and their own bounds.
        if (codeChunk.matches("(?s).*?(?m:^L[0-9]+\\s*\\|).*")) return codeChunk;
        List<String> lines = codeChunk.lines().toList();
        StringBuilder numbered = new StringBuilder();
        for (int i = 0; i < lines.size(); i++) {
            numbered.append('L').append(i + 1).append(" | ").append(lines.get(i)).append('\n');
        }
        return numbered.toString();
    }

    /**
     * Консультация по уязвимости с учетом реального контекста файла
     */
    public String askQuestionAboutVulnerability(SourceFile file, Vulnerability vulnerability, String userQuestion) {
        String lang = detectLanguageFromName(file.getName());

        String prompt = """
                Контекст: В файле "%s" (язык: %s) обнаружена уязвимость "%s" (уровень: %s) на строках %s.
                Описание: %s
                
                Вопрос пользователя: %s
                Ответь кратко, понятно и с примером кода с учетом синтаксиса и специфики языка %s.
                """.formatted(
                file.getName(),
                lang,
                vulnerability.getTitle(),
                vulnerability.getSeverity(),
                vulnerability.getLineRange(),
                vulnerability.getDescription(),
                userQuestion,
                lang
        );

        return chatWithModel(defaultModel, prompt);
    }



    /**
     * Универсальное автоматическое исправление исходного файла на любом языке
     */
    public String fixSourceFile(SourceFile file) {
        String lang = detectLanguageFromName(file.getName());

        String prompt = """
                Ты — эксперт по безопасному рефакторингу программного обеспечения.
                Исправь найденные уязвимости безопасности в следующем файле, строго сохраняя язык программирования (%s), оригинальную логику и архитектуру.
                Верни ИСКЛЮЧИТЕЛЬНО ГОТОВЫЙ ИСПРАВЛЕННЫЙ КОД без каких-либо вводных слов, пояснений и markdown-блоков (без ```).
                
                Файл (%s):
                ```
                %s
                ```
                """.formatted(lang, file.getName(), file.getContent());

        String rawResponse = chatWithModel(defaultModel, prompt);
        String extracted = extractCodeBlock(rawResponse);
        return extracted.isBlank() ? rawResponse.trim() : extracted;
    }

    private String detectLanguageFromName(String fileName) {
        if (fileName == null) return "Unknown";
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".java")) return "Java";
        if (lower.endsWith(".cpp") || lower.endsWith(".cc") || lower.endsWith(".cxx")) return "C++";
        if (lower.endsWith(".c") || lower.endsWith(".h") || lower.endsWith(".hpp")) return "C/C++";
        if (lower.endsWith(".py")) return "Python";
        if (lower.endsWith(".js") || lower.endsWith(".jsx")) return "JavaScript";
        if (lower.endsWith(".ts") || lower.endsWith(".tsx")) return "TypeScript";
        if (lower.endsWith(".go")) return "Go";
        if (lower.endsWith(".cs")) return "C#";
        if (lower.endsWith(".php")) return "PHP";
        return "Unknown";
    }

    private String extractCodeBlock(String text) {
        if (text != null && text.contains("```")) {
            int start = text.indexOf("```");
            int firstNewLine = text.indexOf("\n", start);
            int end = text.lastIndexOf("```");
            if (firstNewLine != -1 && end > firstNewLine) {
                return text.substring(firstNewLine + 1, end).trim();
            }
        }
        return text != null ? text.trim() : "";
    }
}