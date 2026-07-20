package com.analyzer.domain.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SourceFile {
    private String name;
    private String absolutePath;
    private String extension;
    private long sizeInBytes;
    private String content;
    private List<Vulnerability> vulnerabilities = new ArrayList<>(); // <-- Связываем файл с его уязвимостями
}