package com.analyzerweb;

import com.analyzer.service.ai.OllamaClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class WebApiController {
    private final OllamaClient ollama;
    private final WebScanService scans;

    public WebApiController(OllamaClient ollama, WebScanService scans) {
        this.ollama = ollama;
        this.scans = scans;
    }

    @GetMapping("/models")
    public Map<String, Object> models() {
        // OllamaClient returns a default model name even when Ollama is offline.
        return Map.of("models", ollama.getAvailableModels(),
                "notice", "Если Ollama недоступна, список может содержать модель по умолчанию.");
    }

    @PostMapping(path = "/scan", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public WebScanService.ScanView scan(
            @RequestHeader(name = "X-Code-Analyzer", required = false) String client,
            @RequestParam("model") String model,
            @RequestPart("files") List<MultipartFile> files) throws IOException {
        // A non-simple same-origin header prevents third-party form submissions from starting scans.
        if (!"web1".equals(client)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Откройте локальный веб-интерфейс анализатора");
        }
        List<String> available = ollama.getAvailableModels();
        if (!available.contains(model)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Выбранной модели нет в списке Ollama");
        }
        return scans.scan(files, model);
    }

    @PostMapping(path = "/scan-zip", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public WebScanService.ScanView scanZip(
            @RequestHeader(name = "X-Code-Analyzer", required = false) String client,
            @RequestParam("model") String model,
            @RequestPart("archive") MultipartFile archive) throws IOException {
        if (!"web1".equals(client))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Откройте локальный веб-интерфейс анализатора");
        if (!ollama.getAvailableModels().contains(model))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Выбранной модели нет в списке Ollama");
        return scans.scanZip(archive, model);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public org.springframework.http.ResponseEntity<Map<String, String>> badUpload(IllegalArgumentException ex) {
        return org.springframework.http.ResponseEntity.badRequest().body(
                Map.of("error", ex.getMessage() == null ? "Некорректные файлы" : ex.getMessage()));
    }

    @ExceptionHandler(WebScanService.ScanBusyException.class)
    public org.springframework.http.ResponseEntity<Map<String, String>> busy() {
        return org.springframework.http.ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "Другой анализ ещё выполняется. Повторите позже."));
    }

    @ExceptionHandler(IOException.class)
    public org.springframework.http.ResponseEntity<Map<String, String>> inputOutputError() {
        return org.springframework.http.ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Ошибка обработки загруженных файлов. Проверьте журнал приложения."));
    }
}
