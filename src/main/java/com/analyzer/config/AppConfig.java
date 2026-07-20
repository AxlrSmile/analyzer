package com.analyzer.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration // Говорим Spring, что это класс конфигурации бинов
public class AppConfig {

    @Bean // Регистрируем ObjectMapper в контексте Spring
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Полезная настройка для диплома: если ИИ вернет в JSON лишнее поле,
        // которого нет в нашей модели Vulnerability, приложение НЕ упадет с ошибкой
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        return mapper;
    }
}