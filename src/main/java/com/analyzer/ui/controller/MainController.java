package com.analyzer.ui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import org.springframework.stereotype.Component;

@Component // Говорим Spring, что этот класс — управляемый бин
public class MainController {

    @FXML
    private Button scanButton;

    @FXML
    public void initialize() {
        // Метод вызывается автоматически, когда JavaFX загружает интерфейс
        scanButton.setOnAction(event -> handleScanButtonClick());
    }

    private void handleScanButtonClick() {
        System.out.println("Кнопка сканирования нажата! Логика будет тут.");
    }
}