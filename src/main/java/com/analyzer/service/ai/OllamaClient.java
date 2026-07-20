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
        String systemPrompt = """
            You are a Senior Application Security Auditor. Analyze the provided source code chunk for security vulnerabilities.
            You must look for: SQL Injection, XSS, Authentication problems, Weak Cryptography, Hardcoded Secrets, Vulnerable Dependencies.
    
            CRITICAL RULE: Any hardcoded credentials, static URLs (like http://localhost:11434), or hardcoded configuration values (like AI model names) MUST be flagged as a 'Hardcoded Secrets' or 'Improper Configuration' vulnerability with HIGH or MEDIUM severity.
    
            You must return ONLY a JSON array of objects, OR a JSON object containing a "vulnerabilities" array.
            Each vulnerability object must have exactly these fields:
            - "title": short name of vulnerability
            - "severity": HIGH, MEDIUM, or LOW
            - "description": precise explanation
            - "lineRange": approximate lines in the chunk (e.g. "15-18") or "Unknown"
            - "recommendation": how to fix it
    
            If no vulnerabilities are found, return an empty JSON array: []
        """;

        try {
            Map<String, Object> options = Map.of(
                    "temperature", 0.0,
                    "top_p", 0.1,
                    "seed", 42 // Фиксируем генератор случайных чисел
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

            // --- УМНЫЙ И БЕЗОПАСНЫЙ ПАРСИНГ ---
            JsonNode jsonNode = objectMapper.readTree(aiResponseText);

            // Вариант 1: ИИ вернул чистый массив [ {...}, {...} ]
            if (jsonNode.isArray()) {
                return objectMapper.readValue(aiResponseText, new TypeReference<List<Vulnerability>>() {});
            }

            // Вариант 2: ИИ вернул объект { "vulnerabilities": [ ... ] }
            if (jsonNode.isObject()) {
                if (jsonNode.has("vulnerabilities") && jsonNode.get("vulnerabilities").isArray()) {
                    JsonNode arrayNode = jsonNode.get("vulnerabilities");
                    return objectMapper.readValue(arrayNode.toString(), new TypeReference<List<Vulnerability>>() {});
                }

                // Если объект пустой или содержит признаки отсутствия уязвимостей
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
}