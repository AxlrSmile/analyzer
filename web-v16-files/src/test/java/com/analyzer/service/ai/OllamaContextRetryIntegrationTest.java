package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** Ensures evidence hints are sent only on retry, and never bypass citation validation. */
class OllamaContextRetryIntegrationTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SOURCE = "class Demo {\n"
            + "  String sql = \"SELECT id FROM users\" + name;\n"
            + "}\n";
    private static final String VALID = """
            {"vulnerabilities":[{"title":"SQL Injection","severity":"HIGH","cwe":"CWE-89",
            "startLine":2,"endLine":2,"evidence":"String sql = \\"SELECT id FROM users\\" + name;",
            "description":"SQL uses a string concatenation","recommendation":"Use parameters"}]}
            """;
    private static final String WRONG = VALID.replace("String sql = \\\"SELECT id FROM users\\\" + name;",
            "String sql = \\\"SELECT id FROM people\\\" + name;");

    @Test void retryShowsOriginalLinesButStillRequiresExactQuote() throws Exception {
        List<String> prompts = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/generate", exchange -> {
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String prompt = MAPPER.readTree(request).path("prompt").asText();
            prompts.add(prompt);
            byte[] response = MAPPER.writeValueAsBytes(Map.of("response", calls.incrementAndGet() == 1 ? WRONG : VALID));
            exchange.sendResponseHeaders(200, response.length);
            try (var out = exchange.getResponseBody()) { out.write(response); }
        });
        server.start();
        try {
            var client = new OllamaClient(MAPPER, "http://127.0.0.1:" + server.getAddress().getPort(), "test-model");
            var result = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(2, calls.get());
            assertFalse(prompts.getFirst().contains("ПОДСКАЗКА ПО ИСХОДНЫМ СТРОКАМ"));
            assertTrue(prompts.get(1).contains("ПОДСКАЗКА ПО ИСХОДНЫМ СТРОКАМ"));
            assertTrue(prompts.get(1).contains("L2 |   String sql"));
            assertEquals("EVIDENCE_MATCHED", result.getFirst().getModelOutputStatus());
        } finally {
            server.stop(0);
        }
    }
}
