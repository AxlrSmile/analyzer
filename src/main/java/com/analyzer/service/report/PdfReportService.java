package com.analyzer.service.report;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;
import com.lowagie.text.*;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PdfReportService {

    public void generatePdfReport(List<SourceFile> files, String outputPath) throws DocumentException, IOException {
        Document document = new Document(PageSize.A4, 36, 36, 36, 36);
        PdfWriter.getInstance(document, new FileOutputStream(outputPath));

        document.open();

        // Стандартный системный шрифт Windows для поддержки кириллицы
        BaseFont baseFont = BaseFont.createFont("c:/windows/fonts/arial.ttf", BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
        Font mainTitleFont = new Font(baseFont, 18, Font.BOLD, new Color(41, 128, 185));
        Font sectionHeaderFont = new Font(baseFont, 13, Font.BOLD, new Color(44, 62, 80));
        Font normalFont = new Font(baseFont, 10, Font.NORMAL, Color.DARK_GRAY);
        Font boldFont = new Font(baseFont, 10, Font.BOLD, Color.BLACK);
        Font tableHeaderFont = new Font(baseFont, 10, Font.BOLD, Color.WHITE);
        Font vulnTitleFont = new Font(baseFont, 11, Font.BOLD, new Color(192, 57, 43));

        // 1. Заголовок отчета
        Paragraph title = new Paragraph("ОТЧЕТ О БЕЗОПАСНОСТИ И КАЧЕСТВЕ ИСХОДНОГО КОДА", mainTitleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        document.add(title);

        String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss"));
        Paragraph date = new Paragraph("Дата и время сканирования: " + dateStr, normalFont);
        date.setAlignment(Element.ALIGN_CENTER);
        date.setSpacingAfter(20);
        document.add(date);

        // Расчет общей статистики проекта
        long totalFiles = files.size();
        long cleanFiles = files.stream().filter(f -> f.getVulnerabilities().isEmpty()).count();
        long totalVulns = files.stream().mapToLong(f -> f.getVulnerabilities().size()).sum();
        long totalLinesOfCode = files.stream().mapToLong(SourceFile::getLinesOfCode).sum();

        long highSeverityCount = files.stream()
                .flatMap(f -> f.getVulnerabilities().stream())
                .filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("HIGH"))
                .count();

        long mediumSeverityCount = files.stream()
                .flatMap(f -> f.getVulnerabilities().stream())
                .filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("MEDIUM"))
                .count();

        long lowSeverityCount = files.stream()
                .flatMap(f -> f.getVulnerabilities().stream())
                .filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("LOW"))
                .count();

        // 2. Сводная таблица статистики проекта
        Paragraph statsHeader = new Paragraph("1. Общая информация о проекте", sectionHeaderFont);
        statsHeader.setSpacingAfter(8);
        document.add(statsHeader);

        PdfPTable statsTable = new PdfPTable(2);
        statsTable.setWidthPercentage(100);
        statsTable.setWidths(new float[]{1, 1});

        addTableCell(statsTable, "Всего проанализировано файлов:", boldFont, new Color(245, 247, 250));
        addTableCell(statsTable, String.valueOf(totalFiles), normalFont, Color.WHITE);

        addTableCell(statsTable, "Общий объем кода (строк):", boldFont, new Color(245, 247, 250));
        addTableCell(statsTable, String.valueOf(totalLinesOfCode), normalFont, Color.WHITE);

        addTableCell(statsTable, "Файлов без уязвимостей:", boldFont, new Color(245, 247, 250));
        addTableCell(statsTable, String.format("%d (%.1f%%)", cleanFiles, totalFiles > 0 ? (cleanFiles * 100.0 / totalFiles) : 0), normalFont, Color.WHITE);

        addTableCell(statsTable, "Всего обнаружено уязвимостей:", boldFont, new Color(245, 247, 250));
        addTableCell(statsTable, String.valueOf(totalVulns), boldFont, Color.WHITE);

        addTableCell(statsTable, "Распределение по критичности:", boldFont, new Color(245, 247, 250));
        addTableCell(statsTable, String.format("Высокая (HIGH): %d | Средняя (MEDIUM): %d | Низкая (LOW): %d",
                highSeverityCount, mediumSeverityCount, lowSeverityCount), normalFont, Color.WHITE);

        document.add(statsTable);
        document.add(new Paragraph("\n"));

        // 3. Таблица со списком всех файлов
        Paragraph filesHeader = new Paragraph("2. Реестр проверенных файлов", sectionHeaderFont);
        filesHeader.setSpacingAfter(8);
        document.add(filesHeader);

        PdfPTable filesTable = new PdfPTable(3);
        filesTable.setWidthPercentage(100);
        filesTable.setWidths(new float[]{5, 2, 2});

        addTableCell(filesTable, "Имя файла", tableHeaderFont, new Color(52, 73, 94));
        addTableCell(filesTable, "Строк кода", tableHeaderFont, new Color(52, 73, 94));
        addTableCell(filesTable, "Уязвимости", tableHeaderFont, new Color(52, 73, 94));

        for (SourceFile file : files) {
            addTableCell(filesTable, file.getName(), normalFont, Color.WHITE);
            addTableCell(filesTable, String.valueOf(file.getLinesOfCode()), normalFont, Color.WHITE);

            long count = file.getVulnerabilities().size();
            Color statusBg = count > 0 ? new Color(253, 237, 236) : new Color(234, 250, 234);
            addTableCell(filesTable, count > 0 ? count + " шт." : "Чисто", normalFont, statusBg);
        }

        document.add(filesTable);
        document.add(new Paragraph("\n"));

        // 4. Детальные находки уязвимостей
        if (totalVulns > 0) {
            Paragraph detailsHeader = new Paragraph("3. Детальный разбор найденных дефектов", sectionHeaderFont);
            detailsHeader.setSpacingAfter(10);
            document.add(detailsHeader);

            for (SourceFile file : files) {
                if (file.getVulnerabilities().isEmpty()) continue;

                Paragraph fileName = new Paragraph("Файл: " + file.getRelativePath(), sectionHeaderFont);
                fileName.setSpacingBefore(8);
                fileName.setSpacingAfter(6);
                document.add(fileName);

                PdfPTable table = new PdfPTable(3);
                table.setWidthPercentage(100);
                table.setWidths(new float[]{4, 2, 2});

                addTableCell(table, "Уязвимость", tableHeaderFont, new Color(41, 128, 185));
                addTableCell(table, "Критичность", tableHeaderFont, new Color(41, 128, 185));
                addTableCell(table, "Строки", tableHeaderFont, new Color(41, 128, 185));

                for (Vulnerability v : file.getVulnerabilities()) {
                    addTableCell(table, v.getTitle(), normalFont, Color.WHITE);

                    // Раскрашиваем ячейку критичности в зависимости от уровня
                    Color sevBg = Color.WHITE;
                    if ("HIGH".equalsIgnoreCase(v.getSeverity())) sevBg = new Color(242, 215, 213);
                    else if ("MEDIUM".equalsIgnoreCase(v.getSeverity())) sevBg = new Color(252, 243, 207);
                    else if ("LOW".equalsIgnoreCase(v.getSeverity())) sevBg = new Color(212, 239, 223);

                    addTableCell(table, v.getSeverity(), boldFont, sevBg);
                    addTableCell(table, v.getLineRange(), normalFont, Color.WHITE);
                }

                document.add(table);

                // Вывод развернутого описания и рекомендаций по исправлению
                for (Vulnerability v : file.getVulnerabilities()) {
                    Paragraph vDetails = new Paragraph();
                    vDetails.setSpacingBefore(4);
                    vDetails.add(new Chunk("Уязвимость: ", vulnTitleFont));
                    vDetails.add(new Chunk(v.getTitle() + "\n", boldFont));

                    vDetails.add(new Chunk("Описание: ", boldFont));
                    vDetails.add(new Chunk(v.getDescription() + "\n", normalFont));

                    vDetails.add(new Chunk("Рекомендация по исправлению: ", boldFont));
                    vDetails.add(new Chunk(v.getRecommendation() + "\n", normalFont));

                    document.add(vDetails);
                }
            }
        }

        document.close();
    }

    private void addTableCell(PdfPTable table, String text, Font font, Color bgColor) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(6);
        cell.setHorizontalAlignment(Element.ALIGN_LEFT);
        table.addCell(cell);
    }
}