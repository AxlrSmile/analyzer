package com.analyzerweb;

import com.analyzer.service.ai.OllamaClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

/** No auto-apply or write-to-project endpoint is exposed. Loopback access only. */
@RestController
public class WebFixController {
    private final WebFixService service;
    private final OllamaClient ollama;

    public WebFixController(WebFixService service, OllamaClient ollama) {
        this.service = service;
        this.ollama = ollama;
    }

    @PostMapping(path = "/api/fix-preview", consumes = MediaType.APPLICATION_JSON_VALUE)
    public WebFixService.PreviewResponse preview(
            @RequestHeader(name = "X-Code-Analyzer", required = false) String client,
            @RequestBody WebFixService.PreviewRequest request) throws IOException {
        if (!"web1".equals(client)) throw new ForbiddenRequest();
        WebFixPolicy.check(request);
        if (!ollama.getAvailableModels().contains(request.model())) {
            throw new IllegalArgumentException("Выбранная модель отсутствует в списке Ollama");
        }
        return service.preview(request);
    }

    private static class ForbiddenRequest extends RuntimeException { }

    @ExceptionHandler(ForbiddenRequest.class)
    public ResponseEntity<Map<String, String>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Используйте локальный интерфейс Code Security Analyzer"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badInput(IllegalArgumentException ex) {
        String text = ex.getMessage() == null ? "Недопустимые данные" : ex.getMessage();
        return ResponseEntity.badRequest().body(Map.of("error", text.length() > 250
                ? text.substring(0, 250) : text));
    }

    @ExceptionHandler(WebFixService.PreviewBusyException.class)
    public ResponseEntity<Map<String, String>> busy() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "Другое предложение ещё обрабатывается"));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, String>> failed(IOException ex) {
        System.err.println("Web Fix: предложение не сформировано: " + ex.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(Map.of("error", "Предложение не сформировано. Модель могла вернуть некорректный код. "
                        + "Проверьте Ollama и серверный журнал; оригинал не изменён."));
    }
}
