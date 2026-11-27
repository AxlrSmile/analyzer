package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class OllamaStructuredApiTest {
    @Test void sendsSchemaAndAbsoluteLinePrefixesForShortCode() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        AtomicReference<String> payload = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/generate", exchange -> {
            payload.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = "{\"response\":\"{\\\"vulnerabilities\\\":[]}\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) { out.write(body); }
        });
        server.start();
        try {
            OllamaClient client = new OllamaClient(mapper,
                    "http://127.0.0.1:" + server.getAddress().getPort(), "test-model");
            assertTrue(client.analyzeCodeChunk("class Demo {}", "Java", "test-model").isEmpty());
            JsonNode request = mapper.readTree(payload.get());
            assertTrue(request.get("format").isObject());
            assertEquals("object", request.get("format").get("type").asText());
            assertTrue(request.get("prompt").asText().contains("L1 | class Demo {}"));
            assertEquals(0, request.get("options").get("temperature").asInt());
        } finally {
            server.stop(0);
        }
    }
}
