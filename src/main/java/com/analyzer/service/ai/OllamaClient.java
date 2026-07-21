package com.analyzer.service.ai;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class OllamaClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    // Конфигурация по умолчанию
    private static final String OLLAMA_URL = "http://localhost:11434/api/generate";
    private static final String MODEL_NAME = "qwen2.5-coder:7b"; // или deepseek-coder

    public OllamaClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public List<Vulnerability> analyzeCodeChunk(String codeChunk) {
        String systemPrompt = """
            Вы — старший аудитор по информационной безопасности приложений. Проанализируйте предоставленный фрагмент исходного кода на наличие уязвимостей.
            Вы должны искать следующие проблемы: SQL-инъекции, XSS, проблемы аутентификации, слабая криптография, зашитые секреты (hardcoded secrets), уязвимые зависимости.
    
            КРИТИЧЕСКОЕ ПРАВИЛО: Любые зашитые учетные данные, статические URL-адреса локальных сервисов (например, http://localhost:11434) или зашитые параметры конфигурации (например, имена моделей ИИ) ОБЯЗАТЕЛЬНО должны помечаться как уязвимость 'Зашитые секреты' или 'Неправильная конфигурация' с уровнем критичности HIGH или MEDIUM.
    
            ВЫ ДОЛЖНЫ ОТВЕЧАТЬ ИСКЛЮЧИТЕЛЬНО НА РУССКОМ ЯЗЫКЕ (поля title, severity, description, recommendation).
    
            Вы должны вернуть ТОЛЬКО массив JSON из объектов ИЛИ объект JSON, содержащий массив с ключом "vulnerabilities".
            Каждый объект уязвимости должен иметь строго следующие поля (имена полей остаются на английском!):
            - "title": краткое название уязвимости на русском
            - "severity": строго одно из значений: HIGH, MEDIUM или LOW
            - "description": подробное объяснение проблемы на русском
            - "lineRange": примерный диапазон строк в фрагменте (например, "15-18") или "Неизвестно"
            - "recommendation": четкая инструкция по исправлению на русском
    
            Если уязвимости не найдены, верните пустой массив JSON: []
    """;

        try {
            Map<String, Object> options = Map.of(
                    "temperature", 0.0,
                    "top_p", 0.1,
                    "seed", 42
            );

            Map<String, Object> requestBody = Map.of(
                    "model", MODEL_NAME,
                    "prompt", "Code to analyze:\n\n" + codeChunk,
                    "system", systemPrompt,
                    "stream", false,
                    "format", "json",
                    "options", options
            );

            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofMinutes(5))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                System.err.println("Ollama API returned error status: " + response.statusCode());
                return new ArrayList<>();
            }

            JsonNode rootNode = objectMapper.readTree(response.body());
            String aiResponseText = rootNode.get("response").asText().trim();

            JsonNode jsonNode = objectMapper.readTree(aiResponseText);

            if (jsonNode.isArray()) {
                return objectMapper.readValue(aiResponseText, new TypeReference<List<Vulnerability>>() {});
            }

            if (jsonNode.isObject()) {
                if (jsonNode.has("vulnerabilities") && jsonNode.get("vulnerabilities").isArray()) {
                    JsonNode arrayNode = jsonNode.get("vulnerabilities");
                    return objectMapper.readValue(arrayNode.toString(), new TypeReference<List<Vulnerability>>() {});
                }
                System.out.println("ИИ вернул объект без уязвимостей: " + aiResponseText);
            }

            return new ArrayList<>();

        } catch (IOException | InterruptedException e) {
            System.err.println("Error communication with Ollama: " + e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new ArrayList<>();
        }
    }

    /**
     * Консультация с ИИ по конкретной найденной уязвимости.
     */
    public String askQuestionAboutVulnerability(SourceFile sourceFile, Vulnerability vulnerability, String userQuestion) {
        String systemPrompt = """
            Вы — Senior Java/Security Engineer. Ваша задача — проконсультировать разработчика по найденной уязвимости в его коде.
            Давайте четкие, профессиональные и исчерпывающие ответы НА РУССКОМ ЯЗЫКЕ.
            Если пользователь просит пример кода — приведите полностью исправленный и безопасный вариант этого фрагмента кода с комментариями.
            """;

        String prompt = String.format("""
            Контекст файла: %s
            Уязвимость: %s (Критичность: %s, Строки: %s)
            Описание проблемы: %s
            
            Исходный код файла:
            ```
            %s
            ```
            
            Вопрос разработчика: %s
            """,
                sourceFile.getName(),
                vulnerability.getTitle(),
                vulnerability.getSeverity(),
                vulnerability.getLineRange(),
                vulnerability.getDescription(),
                sourceFile.getContent(),
                userQuestion
        );

        return executeOllamaRequest(prompt, systemPrompt);
    }

    /**
     * Генерация полностью исправленной версии файла.
     */
    public String fixSourceFile(SourceFile file) {
        String systemPrompt = "Ты — Senior Java Security Architect. Твоя задача — написать безопасный, чистый и исправленный код без уязвимостей.";

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Ниже представлен исходный код файла '%s', в котором обнаружены следующие уязвимости:\n", file.getName()));

        for (Vulnerability v : file.getVulnerabilities()) {
            sb.append(String.format("- %s (Строки: %s): %s\n", v.getTitle(), v.getLineRange(), v.getDescription()));
        }

        sb.append("\nВот исходный код файла:\n```java\n")
                .append(file.getContent())
                .append("\n```\n\n")
                .append("Перепиши этот код так, чтобы полностью устранить все указанные уязвимости. ")
                .append("ВАЖНО: В ответе верни ИСКЛЮЧИТЕЛЬНО готовый исправленный код Java внутри тегов ```java ... ``` без лишних приветствий и пояснений.");

        String response = executeOllamaRequest(sb.toString(), systemPrompt);

        return extractCodeBlock(response);
    }

    /**
     * Универсальный private-метод для отправки любого текстового промпта в Ollama.
     */
    private String executeOllamaRequest(String prompt, String systemPrompt) {
        try {
            Map<String, Object> options = Map.of(
                    "temperature", 0.1
            );

            Map<String, Object> requestBody = Map.of(
                    "model", MODEL_NAME,
                    "prompt", prompt,
                    "system", systemPrompt,
                    "stream", false,
                    "options", options
            );

            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofMinutes(4))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode rootNode = objectMapper.readTree(response.body());
                return rootNode.get("response").asText().trim();
            } else {
                return "Ошибка обращения к ИИ: код ответа " + response.statusCode();
            }

        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return "Ошибка связи с Ollama: " + e.getMessage();
        }
    }

    private String extractCodeBlock(String markdown) {
        if (markdown == null || markdown.isEmpty()) return "";

        if (markdown.contains("```java")) {
            int start = markdown.indexOf("```java") + 7;
            int end = markdown.indexOf("```", start);
            if (end != -1) {
                return markdown.substring(start, end).trim();
            }
        } else if (markdown.contains("```")) {
            int start = markdown.indexOf("```") + 3;
            int end = markdown.indexOf("```", start);
            if (end != -1) {
                return markdown.substring(start, end).trim();
            }
        }
        return markdown.trim();
    }
}