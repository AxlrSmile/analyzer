package com.analyzer.service.ai;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.analyzer.ui.controller.MainController;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    private static final String DEFAULT_MODEL_NAME = "qwen2.5-coder:7b";

    public OllamaClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Получение списка всех локально скачанных моделей из Ollama
     */
    public List<String> getAvailableModels() {
        List<String> models = new ArrayList<>();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_BASE_URL + "/api/tags"))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode modelsNode = root.get("models");
                if (modelsNode != null && modelsNode.isArray()) {
                    for (JsonNode model : modelsNode) {
                        if (model.has("name")) {
                            models.add(model.get("name").asText());
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Ошибка при получении списка моделей Ollama: " + e.getMessage());
        }
        return models;
    }

    /**
     * Отправка произвольного сообщения ИИ с указанием конкретной модели (для одиночных промптов)
     */
    public String chatWithModel(String modelName, String userPrompt) {
        String systemPrompt = "Вы — универсальный и высококвалифицированный ИИ-ассистент. Отвечайте на вопросы пользователя вежливо, четко и структурировано на русском языке.";
        String effectiveModel = (modelName != null && !modelName.isBlank()) ? modelName : DEFAULT_MODEL_NAME;
        return executeOllamaRequest(userPrompt, systemPrompt, effectiveModel);
    }

    /**
     * Отправка полной истории диалога через Ollama Chat API (/api/chat)
     * Ожидает роли: "user" или "assistant"
     */
    public String chatWithHistory(String modelName, List<MainController.ChatMessage> history) {
        String effectiveModel = (modelName != null && !modelName.isBlank()) ? modelName : DEFAULT_MODEL_NAME;

        try {
            ObjectNode requestJson = objectMapper.createObjectNode();
            requestJson.put("model", effectiveModel);
            requestJson.put("stream", false);

            ArrayNode messagesArray = requestJson.putArray("messages");

            // 1. Системный промпт как заголовок контекста
            ObjectNode systemMsgNode = messagesArray.addObject();
            systemMsgNode.put("role", "system");
            systemMsgNode.put("content", "Вы — универсальный и высококвалифицированный ИИ-ассистент. Отвечайте на вопросы пользователя вежливо, четко и структурировано на русском языке.");

            // 2. Формируем историю сообщений диалога
            for (MainController.ChatMessage msg : history) {
                ObjectNode msgNode = messagesArray.addObject();
                msgNode.put("role", msg.getRole()); // "user" или "assistant"
                msgNode.put("content", msg.getContent());
            }

            String jsonPayload = objectMapper.writeValueAsString(requestJson);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_BASE_URL + "/api/chat"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofMinutes(4))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode responseJson = objectMapper.readTree(response.body());
                if (responseJson.has("message") && responseJson.get("message").has("content")) {
                    return responseJson.get("message").get("content").asText().trim();
                }
                return "⚠️ Ошибка: не удалось извлечь поле message.content из ответа Ollama.";
            } else {
                return " Ошибка обращения к Ollama Chat API: код ответа " + response.statusCode();
            }

        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            e.printStackTrace();
            return "❌ Ошибка при вызове /api/chat: " + e.getMessage();
        }
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
                    "model", DEFAULT_MODEL_NAME,
                    "prompt", "Code to analyze:\n\n" + codeChunk,
                    "system", systemPrompt,
                    "stream", false,
                    "format", "json",
                    "options", options
            );

            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_BASE_URL + "/api/generate"))
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

        return executeOllamaRequest(prompt, systemPrompt, DEFAULT_MODEL_NAME);
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

        String response = executeOllamaRequest(sb.toString(), systemPrompt, DEFAULT_MODEL_NAME);

        return extractCodeBlock(response);
    }

    /**
     * Универсальный private-метод для отправки любого текстового промпта в Ollama через /api/generate
     */
    private String executeOllamaRequest(String prompt, String systemPrompt, String modelName) {
        try {
            Map<String, Object> options = Map.of(
                    "temperature", 0.1
            );

            Map<String, Object> requestBody = Map.of(
                    "model", modelName,
                    "prompt", prompt,
                    "system", systemPrompt,
                    "stream", false,
                    "options", options
            );

            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_BASE_URL + "/api/generate"))
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