package com.analyzer.ui.controller;

import com.analyzer.service.scanner.ProjectScanner;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.List;

@Component
public class MainController {

    @FXML
    private Button scanButton;

    // Зависимость от абстракции (SOLID: Interface Segregation & Dependency Inversion)
    private final ProjectScanner projectScanner;

    // Внедряем сканер через конструктор. Spring Boot автоматически подставит ProjectScannerImpl
    public MainController(ProjectScanner projectScanner) {
        this.projectScanner = projectScanner;
    }

    @FXML
    public void initialize() {
        scanButton.setOnAction(event -> handleScanButtonClick());
    }

    private void handleScanButtonClick() {
        // Создаем диалоговое окно выбора папки от JavaFX
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Выберите папку с исходным кодом проекта");

        // Получаем текущую Stage (окно), чтобы сделать диалог модальным
        Stage stage = (Stage) scanButton.getScene().getWindow();
        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            System.out.println("Выбрана директория для сканирования: " + selectedDirectory.getAbsolutePath());

            try {
                // Вызываем наш сервис сканирования
                List<File> codeFiles = projectScanner.scanDirectory(selectedDirectory);

                System.out.println("--- Результаты сканирования ---");
                System.out.println("Всего найдено подходящих файлов: " + codeFiles.size());

                // Временно выведем первые 5 файлов для проверки
                codeFiles.stream()
                        .limit(5)
                        .forEach(file -> System.out.println(" - " + file.getName() + " (" + file.length() + " байт)"));

            } catch (IOException e) {
                System.err.println("Ошибка при сканировании директории: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            System.out.println("Выбор директории отменен пользователем.");
        }
    }
}