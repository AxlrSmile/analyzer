package com.analyzerweb;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Strict policy for the local, read-only browser prototype. No ZIP extraction or code execution. */
public final class WebUploadPolicy {
    public static final int MAX_FILES = 5;
    public static final int MAX_FILE_BYTES = 256 * 1024;
    public static final int MAX_TOTAL_BYTES = 512 * 1024;
    public static final int MAX_LINES = 500;

    private static final Set<String> EXTENSIONS = Set.of(
            "java", "kt", "scala", "c", "h", "cpp", "cc", "cxx", "hpp",
            "py", "js", "mjs", "jsx", "ts", "tsx", "php", "rb", "go", "rs", "cs", "sql");
    private static final Pattern SAFE_NAME = Pattern.compile("[\\p{L}\\p{N}_ .()\\-]{1,120}");
    private static final Pattern WIN_DEVICE = Pattern.compile("(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])");

    private WebUploadPolicy() { }

    public static String checkedName(String name) {
        if (name == null || !SAFE_NAME.matcher(name).matches()
                || name.startsWith(".") || name.endsWith(".") || name.endsWith(" ")
                || name.contains("..") || name.contains("/") || name.contains("\\")) {
            throw new IllegalArgumentException("Недопустимое имя исходного файла");
        }
        int dot = name.lastIndexOf('.');
        if (dot < 1 || dot == name.length() - 1) {
            throw new IllegalArgumentException("У файла должно быть поддерживаемое расширение");
        }
        if (WIN_DEVICE.matcher(name.substring(0, dot)).matches()) {
            throw new IllegalArgumentException("Зарезервированное имя файла Windows");
        }
        String ext = name.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (!EXTENSIONS.contains(ext)) {
            throw new IllegalArgumentException("Неподдерживаемое расширение: ." + ext);
        }
        return name;
    }

    public static void checkBytes(byte[] contents) {
        if (contents == null || contents.length == 0 || contents.length > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("Пустой или слишком большой файл (максимум 256 КБ)");
        }
        for (byte b : contents) {
            if (b == 0) throw new IllegalArgumentException("Бинарные файлы не принимаются");
        }
        long lines = new String(contents, StandardCharsets.UTF_8).lines().limit(MAX_LINES + 1L).count();
        if (lines > MAX_LINES) {
            throw new IllegalArgumentException("Слишком много строк в файле (максимум 500)");
        }
    }
}
