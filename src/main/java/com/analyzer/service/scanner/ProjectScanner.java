package com.analyzer.service.scanner;

import com.analyzer.domain.model.SourceFile;
import com.analyzer.domain.model.Vulnerability;

import java.io.File;
import java.util.List;

public interface ProjectScanner {
    List<SourceFile> scanDirectory(File directory);
    List<Vulnerability> analyzeFile(SourceFile file);
}