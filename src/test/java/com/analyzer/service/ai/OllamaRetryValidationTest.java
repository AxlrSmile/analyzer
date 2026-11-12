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

class OllamaRetryValidationTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private static final String SOURCE = "class Demo {\n  String sql = \"SELECT id FROM users\" + name;\n}\n";
    private static final String CORRECT = """
            {"vulnerabilities":[{"title":"SQL Injection","severity":"HIGH","cwe":"CWE-89",
            "startLine":2,"endLine":2,"evidence":"String sql = \\\"SELECT id FROM users\\\" + name;",
            "description":"SQL string uses input","recommendation":"Use parameters"}]}
            """;
    private static final String WRONG = CORRECT.replace("String sql = \\\"SELECT id FROM users\\\" + name;",
            "String sql = \\\"SELECT id FROM people\\\" + name;");

    @Test void retriesOneInvalidCitationAndAcceptsCorrectedResponse() throws Exception {
        var calls = new AtomicInteger();
        var prompts = new ArrayList<String>();
        try (Server server = new Server(i -> {
            calls.incrementAndGet();
            prompts.add(i);
            return i.contains("ПОВТОРНЫЙ ЗАПРОС") ? CORRECT : WRONG;
        })) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var result = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, result.size());
            assertEquals(2, calls.get());
            assertTrue(prompts.get(1).contains("ПОВТОРНЫЙ ЗАПРОС"));
        }
    }

    @Test void stillInvalidAfterRetryRetainsUnverifiedCandidateNotClean() throws Exception {
        var calls = new AtomicInteger();
        try (Server server = new Server(i -> { calls.incrementAndGet(); return WRONG; })) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var result = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, result.size());
            assertEquals("EVIDENCE_UNVERIFIED", result.getFirst().getModelOutputStatus());
            assertEquals("  String sql = \"SELECT id FROM users\" + name;", result.getFirst().getSourceExcerpt());
            assertEquals(2, calls.get());
        }
    }

    @Test void secondAttemptCannotSilentlyDropPreviouslyReportedCandidates() throws Exception {
        var calls = new AtomicInteger();
        try (Server server = new Server(i -> {
            calls.incrementAndGet();
            return i.contains("ПОВТОРНЫЙ ЗАПРОС") ? "{\"vulnerabilities\":[]}" : WRONG;
        })) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var result = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, result.size());
            assertEquals("EVIDENCE_UNVERIFIED", result.getFirst().getModelOutputStatus());
            assertEquals(2, calls.get());
        }
    }

    @Test void successfulEmptyFirstAnswerNeedsNoRetry() throws Exception {
        var calls = new AtomicInteger();
        try (Server server = new Server(i -> { calls.incrementAndGet(); return "{\"vulnerabilities\":[]}"; })) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            assertTrue(client.analyzeCodeChunk(SOURCE, "Java", "test-model").isEmpty());
            assertEquals(1, calls.get());
        }
    }

    @Test void brokenMultilineEvidenceRetainsCandidateWithoutVerification() throws Exception {
        String multiline = CORRECT.replace("String sql =", "String sql =\\n");
        try (Server server = new Server(i -> multiline)) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var findings = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, findings.size());
            assertEquals("EVIDENCE_UNVERIFIED", findings.getFirst().getModelOutputStatus());
            assertNotNull(findings.getFirst().getSourceExcerpt());
        }
    }

    @Test void partialResponseKeepsValidCandidateAndMarksMissingCandidate() throws Exception {
        String wrongCwe = CORRECT.replace("CWE-89", "CWE-0");
        String mixed = CORRECT.replace("]}", "," + wrongCwe.substring(wrongCwe.indexOf('[') + 1, wrongCwe.lastIndexOf(']')) + "]}");
        try (Server server = new Server(i -> mixed)) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var findings = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, findings.size());
            assertEquals("PARTIAL_RESPONSE", findings.getFirst().getModelOutputStatus());
        }
    }

    @Test void secondAttemptWithFewerCandidatesRetainsFirstBatchForReview() throws Exception {
        String wrongCwe = CORRECT.replace("CWE-89", "CWE-0");
        String mixed = CORRECT.replace("]}", "," + wrongCwe.substring(wrongCwe.indexOf('[') + 1, wrongCwe.lastIndexOf(']')) + "]}");
        try (Server server = new Server(i -> i.contains("ПОВТОРНЫЙ ЗАПРОС") ? CORRECT : mixed)) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            var findings = client.analyzeCodeChunk(SOURCE, "Java", "test-model");
            assertEquals(1, findings.size());
            assertEquals("PARTIAL_RESPONSE", findings.getFirst().getModelOutputStatus());
        }
    }

    @Test void allInvalidCweCandidatesStillCauseFileFailure() throws Exception {
        try (Server server = new Server(i -> CORRECT.replace("CWE-89", "CWE-0"))) {
            var client = new OllamaClient(mapper, server.url(), "test-model");
            assertThrows(IllegalStateException.class,
                    () -> client.analyzeCodeChunk(SOURCE, "Java", "test-model"));
        }
    }

    private interface Handler { String reply(String request); }
    private final class Server implements AutoCloseable {
        final HttpServer server;
        Server(Handler handler) throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/generate", exchange -> {
                String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String prompt = mapper.readTree(request).path("prompt").asText();
                byte[] response = mapper.writeValueAsBytes(Map.of("response", handler.reply(prompt)));
                exchange.sendResponseHeaders(200, response.length);
                try (var out = exchange.getResponseBody()) { out.write(response); }
            });
            server.start();
        }
        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }
        @Override public void close() { server.stop(0); }
    }
}
