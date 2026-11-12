package com.analyzer.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OllamaClientTest {

    private HttpServer server;
    private OllamaClient client;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        client = new OllamaClient(new ObjectMapper(),
                "http://127.0.0.1:" + server.getAddress().getPort(), "test-model");
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void returnsEmptyListOnlyOnSuccessfulCleanAnalysis() {
        mockResponse(200, "{\"response\":\"{\\\"vulnerabilities\\\":[]}\"}");
        assertEquals(0, client.analyzeCodeChunk("int x = 1;", "Java").size());
    }

    @Test
    void httpErrorIsNotMistakenForCleanCode() {
        mockResponse(500, "{\"error\":\"model unavailable\"}");
        assertThrows(IllegalStateException.class,
                () -> client.analyzeCodeChunk("int x = 1;", "Java"));
    }

    @Test
    void malformedResultIsNotMistakenForCleanCode() {
        mockResponse(200, "{\"response\":\"{\\\"unexpected\\\":[]}\"}");
        assertThrows(IllegalStateException.class,
                () -> client.analyzeCodeChunk("int x = 1;", "Java"));
    }

    private void mockResponse(int status, String body) {
        server.createContext("/api/generate", exchange -> respond(exchange, status, body));
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var stream = exchange.getResponseBody()) {
            stream.write(bytes);
        }
    }
}
