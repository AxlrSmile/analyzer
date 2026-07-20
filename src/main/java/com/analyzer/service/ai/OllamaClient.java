package com.analyzer.service.ai;

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

    // Конфигурация по умолчанию (можно вынести в application.properties)
    private static final String OLLAMA_URL = "http://localhost:11434/api/generate";
    private static final String MODEL_NAME = "qwen2.5-coder:7b"; // или deepseek-coder

    public OllamaClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        // Настраиваем HttpClient с таймаутом (ИИ может думать долго)
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public List<Vulnerability> analyzeCodeChunk(String codeChunk) {
        // Формируем жесткий системный промпт для разбора уязвимостей
        String systemPrompt = """
            You are a Senior Application Security Auditor. Analyze the provided source code chunk for security vulnerabilities.
            You must look for: SQL Injection, XSS, Authentication problems, Weak Cryptography, Hardcoded Secrets, Vulnerable Dependencies.
            
            CRITICAL: You must return ONLY a JSON array of objects. Do not include markdown code blocks like ```json.
            Each object in the array must have exactly these fields:
            - "title": short name of vulnerability
            - "severity": HIGH, MEDIUM, or LOW
            - "description": precise explanation of why this is a vulnerability
            - "lineRange": approximate lines in the chunk (e.g. "15-18") or "Unknown"
            - "recommendation": how to fix this secure issue
            
            If no vulnerabilities are found, return an empty JSON array: []
            """;

        try {
            // Собираем тело запроса в Map для последующей конвертации в JSON
            Map<String, Object> requestBody = Map.of(
                    "model", MODEL_NAME,
                    "prompt", "Code to analyze:\n\n" + codeChunk,
                    "system", systemPrompt,
                    "stream", false, // Нам нужен полный ответ сразу, а не поток токенов
                    "format", "json" // Заставляем Ollama контролировать JSON-формат на выходе модели
            );

            String jsonPayload = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OLLAMA_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofMinutes(5)) // Таймаут на генерацию — до 5 минут
                    .build();

            // Отправляем синхронный запрос
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                System.err.println("Ollama API returned error status: " + response.statusCode());
                return new ArrayList<>();
            }

            // Парсим ответ от Ollama. Она возвращает JSON вида: { "response": "твой_форматированный_текст", ... }
            JsonNode rootNode = objectMapper.readTree(response.body());
            String aiResponseText = rootNode.get("response").asText();

            // Конвертируем строку-массив от ИИ в типизированный список Java-объектов
            return objectMapper.readValue(aiResponseText, new TypeReference<List<Vulnerability>>() {});

        } catch (IOException | InterruptedException e) {
            System.err.println("Error communication with Ollama: " + e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new ArrayList<>();
        }
    }
}