package com.analyzer.domain.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SourceFile {
    private String name;
    private String absolutePath;
    private String extension;
    private long sizeInBytes;
}