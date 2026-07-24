package com.analyzer.service.agent;

import com.analyzer.service.ai.OllamaClient;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

@Service
public class AgentService {

    private final OllamaClient ollamaClient;
    private final ObjectMapper objectMapper;

    public AgentService(OllamaClient ollamaClient, ObjectMapper objectMapper) {
        this.ollamaClient = ollamaClient;
        this.objectMapper = objectMapper;
    }

    /**
     * DTO структуры задачи, которую планирует агент
     */
    public static class FileTask {
        private String relativePath; // Например: "src/main/java/com/example/Controller.java"
        private String description;  // Описание назначения файла

        public String getRelativePath() { return relativePath; }
        public void setRelativePath(String relativePath) { this.relativePath = relativePath; }

        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }

    /**
     * Запуск процесса генерации проекта по заданному промпту
     */
    public void executeAgentTask(File targetDir, String userPrompt, String modelName, Consumer<String> logger) throws Exception {
        logger.accept("🤖 **Агент запущен.** Выполняется анализ задачи и планирование структуры проекта...");

        // 1. Планирование: Получаем список файлов для создания
        List<FileTask> tasks = planProjectStructure(userPrompt, modelName);

        if (tasks.isEmpty()) {
            logger.accept("⚠️ Агент не смог составить план файлов или проект не требует создания файлов.");
            return;
        }

        logger.accept("📋 **Составлен план создания файлов (" + tasks.size() + "):**");
        for (FileTask task : tasks) {
            logger.accept(" - `" + task.getRelativePath() + "`: " + task.getDescription());
        }

        // 2. Генерация и запись каждого файла
        for (int i = 0; i < tasks.size(); i++) {
            FileTask task = tasks.get(i);
            logger.accept(String.format("⏳ **[%d/%d] Генерация файла:** `%s`...", i + 1, tasks.size(), task.getRelativePath()));

            String fileContent = generateFileContent(userPrompt, task, modelName);

            // Запись на диск
            Path fullPath = Paths.get(targetDir.getAbsolutePath(), task.getRelativePath());
            Files.createDirectories(fullPath.getParent()); // Создаем папки если их нет
            Files.writeString(fullPath, fileContent);

            logger.accept("✅ Файл записан: `" + task.getRelativePath() + "`");
        }

        logger.accept("🎉 **Генерация проекта успешно завершена!** Все файлы созданы в: `" + targetDir.getAbsolutePath() + "`");
    }

    private List<FileTask> planProjectStructure(String userPrompt, String modelName) {
        String systemPrompt = """
            Вы — Senior Software Architect. Пользователь просит создать проект или модуль.
            Ваша задача — составить список файлов (с относительными путями), которые необходимо создать.
            
            ВЫ ДОЛЖНЫ ВЕРНУТЬ ТОЛЬКО JSON-МАССИВ объектов с полями:
            - "relativePath": относительный путь к файлу (например: "src/main/java/com/app/Main.java" или "pom.xml")
            - "description": краткое описание файла
            
            Пример ответа:
            [
              {"relativePath": "pom.xml", "description": "Maven конфигурация"},
              {"relativePath": "src/main/java/com/example/App.java", "description": "Главный класс приложения"}
            ]
            """;

        String response = ollamaClient.chatWithModel(modelName, systemPrompt + "\n\nЗапрос пользователя: " + userPrompt);

        try {
            String jsonArray = extractJson(response);
            return objectMapper.readValue(jsonArray, new TypeReference<List<FileTask>>() {});
        } catch (Exception e) {
            System.err.println("Ошибка парсинга плана агента: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private String generateFileContent(String userPrompt, FileTask task, String modelName) {
        String systemPrompt = String.format("""
            Вы — Senior Developer. Напишите ПОЛНЫЙ, рабочий и чистый код для файла: %s.
            Описание файла: %s.
            Общая цель проекта: %s.
            
            ВАЖНО: Верните ТОЛЬКО код внутри тегов ```java (или нужного языка) без вступительных текстов и вежливых фраз.
            """, task.getRelativePath(), task.getDescription(), userPrompt);

        String rawResponse = ollamaClient.chatWithModel(modelName, systemPrompt);
        return extractCodeBlock(rawResponse);
    }

    private String extractJson(String text) {
        if (text.contains("[")) {
            int start = text.indexOf("[");
            int end = text.lastIndexOf("]");
            if (end != -1 && end > start) {
                return text.substring(start, end + 1);
            }
        }
        return "[]";
    }

    private String extractCodeBlock(String markdown) {
        if (markdown == null || markdown.isEmpty()) return "";
        if (markdown.contains("```")) {
            int start = markdown.indexOf("```");
            int firstNewLine = markdown.indexOf("\n", start);
            int end = markdown.indexOf("```", firstNewLine);
            if (firstNewLine != -1 && end != -1) {
                return markdown.substring(firstNewLine + 1, end).trim();
            }
        }
        return markdown.trim();
    }
}