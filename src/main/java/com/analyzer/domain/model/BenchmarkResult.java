package com.analyzer.domain.model;

public class BenchmarkResult {
    private String modelName;
    private int totalFiles;
    private int truePositives;   // Найдено верно
    private int falsePositives;  // Ложные тревоги
    private int trueNegatives;   // Чистые файлы определены верно
    private int falseNegatives;  // Пропущенные баги
    private double precision;
    private double recall;
    private double f1Score;
    private double totalTimeSec;
    private double avgTimePerFileSec;

    public BenchmarkResult(String modelName, int totalFiles, int tp, int fp, int tn, int fn, double totalTimeSec) {
        this.modelName = modelName;
        this.totalFiles = totalFiles;
        this.truePositives = tp;
        this.falsePositives = fp;
        this.trueNegatives = tn;
        this.falseNegatives = fn;
        this.totalTimeSec = totalTimeSec;
        this.avgTimePerFileSec = totalFiles > 0 ? totalTimeSec / totalFiles : 0;

        this.precision = (tp + fp) > 0 ? ((double) tp / (tp + fp)) * 100.0 : 0.0;
        this.recall = (tp + fn) > 0 ? ((double) tp / (tp + fn)) * 100.0 : 0.0;
        this.f1Score = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0.0;
    }

    public String getModelName() { return modelName; }
    public int getTotalFiles() { return totalFiles; }
    public int getTruePositives() { return truePositives; }
    public int getFalsePositives() { return falsePositives; }
    public int getTrueNegatives() { return trueNegatives; }
    public int getFalseNegatives() { return falseNegatives; }
    public String getPrecisionFormatted() { return String.format("%.1f%%", precision); }
    public String getRecallFormatted() { return String.format("%.1f%%", recall); }
    public String getF1ScoreFormatted() { return String.format("%.1f%%", f1Score); }
    public String getTotalTimeFormatted() { return String.format("%.2f с", totalTimeSec); }
    public String getAvgTimeFormatted() { return String.format("%.2f с", avgTimePerFileSec); }
}