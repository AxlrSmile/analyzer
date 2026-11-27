package com.analyzerweb;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** ZIP files are read as data. No archive entry is extracted or executed by the parser. */
public final class WebZipPolicy {
    public static final int MAX_ARCHIVE_BYTES = 2 * 1024 * 1024;
    public static final int MAX_SOURCE_FILES = 30;
    public static final int MAX_SOURCE_TOTAL_BYTES = 1024 * 1024;
    public static final int MAX_ENTRIES = 200;
    public static final int MAX_INFLATED_BYTES = 4 * 1024 * 1024;
    private static final Pattern SEGMENT = Pattern.compile("[\\p{L}\\p{N}_ .()\\-]{1,120}");
    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", ".idea", ".venv", ".venv-semgrep", "node_modules", "target", "build", "dist", "__macosx");

    private WebZipPolicy() { }

    public record Source(String path, byte[] bytes) { }

    public static List<Source> read(byte[] archive) throws IOException {
        if (archive == null || archive.length == 0 || archive.length > MAX_ARCHIVE_BYTES)
            throw new IllegalArgumentException("ZIP должен быть не больше 2 МБ");
        if (archive.length < 4 || archive[0] != 'P' || archive[1] != 'K')
            throw new IllegalArgumentException("Файл не похож на ZIP-архив");
        List<Source> sources = new ArrayList<>();
        Set<String> names = new HashSet<>();
        int entries = 0;
        long inflated = 0;
        long sourceBytes = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) throw new IllegalArgumentException("ZIP содержит слишком много записей (максимум 200)");
                String path = entry.getName();
                if (path == null || path.isBlank()) throw new IllegalArgumentException("Недопустимый путь в ZIP");
                if (path.contains("\\") || path.startsWith("/") || path.contains(":") || path.length() > 320)
                    throw new IllegalArgumentException("Недопустимый путь в ZIP: " + path);
                boolean directory = entry.isDirectory();
                String normalized = directory && path.endsWith("/") ? path.substring(0, path.length()-1) : path;
                String[] parts = normalized.split("/", -1);
                if (parts.length == 0 || parts.length > 9) throw new IllegalArgumentException("Слишком глубокий путь в ZIP");
                boolean ignored = false;
                for (String part : parts) {
                    if (part.equals(".") || part.equals("..") || part.endsWith(" ") || part.contains(".."))
                        throw new IllegalArgumentException("Недопустимый компонент пути в ZIP");
                    if (part.startsWith(".") || IGNORED_DIRS.contains(part.toLowerCase(Locale.ROOT))) ignored = true;
                    if (!ignored && !SEGMENT.matcher(part).matches()) ignored = true;
                }
                if (directory) continue;
                boolean source = !ignored && supported(parts[parts.length - 1]);
                ByteArrayOutputStream data = source ? new ByteArrayOutputStream() : null;
                byte[] buffer = new byte[8192];
                int count;
                long entryBytes = 0;
                while ((count = zis.read(buffer)) != -1) {
                    entryBytes += count;
                    inflated += count;
                    if (inflated > MAX_INFLATED_BYTES) throw new IllegalArgumentException("ZIP превышает лимит распакованных данных 4 МБ");
                    if (source) {
                        if (entryBytes > WebUploadPolicy.MAX_FILE_BYTES)
                            throw new IllegalArgumentException("Исходник в ZIP больше 256 КБ: " + path);
                        data.write(buffer, 0, count);
                    }
                }
                if (source) {
                    if (sources.size() == MAX_SOURCE_FILES) throw new IllegalArgumentException("В ZIP более 30 исходных файлов");
                    sourceBytes += entryBytes;
                    if (sourceBytes > MAX_SOURCE_TOTAL_BYTES) throw new IllegalArgumentException("Суммарный размер исходников превышает 1 МБ");
                    if (!names.add(normalized.toLowerCase(Locale.ROOT)))
                        throw new IllegalArgumentException("Повторяющийся путь исходника в ZIP");
                    byte[] contents = data.toByteArray();
                    WebUploadPolicy.checkBytes(contents);
                    sources.add(new Source(normalized, contents));
                }
            }
        }
        if (sources.isEmpty()) throw new IllegalArgumentException("В ZIP нет подходящих файлов исходного кода");
        return List.copyOf(sources);
    }

    private static boolean supported(String filename) {
        try { WebUploadPolicy.checkedName(filename); return true; }
        catch (IllegalArgumentException ex) { return false; }
    }
}
