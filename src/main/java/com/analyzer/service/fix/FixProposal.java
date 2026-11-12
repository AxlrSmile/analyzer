package com.analyzer.service.fix;

import java.nio.file.Path;

/**
 * An untrusted model suggestion. No source-file mutation occurs when this record is made.
 * A proposal must be explicitly reviewed and exported to a DIFFERENT file.
 */
public record FixProposal(Path sourcePath, String baselineSha256, String originalContent,
                          String proposedContent, String modelName, String reviewNotes,
                          String diffPreview) {
}
