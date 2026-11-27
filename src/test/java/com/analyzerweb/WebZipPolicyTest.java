package com.analyzerweb;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class WebZipPolicyTest {
    private static byte[] archive(Map<String, String> entries) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (var item : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(item.getKey()));
                zip.write(item.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    @Test void readsNestedSourceFilesAndSkipsMetadata() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        entries.put("project/README.md", "Some markdown");
        entries.put("project/.gitignore", "target");
        entries.put("project/src/main/java/Case008.java", "class Case008 {}\n");
        entries.put("project/src/app.py", "print('test')\n");
        var result = WebZipPolicy.read(archive(entries));
        assertEquals(2, result.size());
        assertEquals("project/src/main/java/Case008.java", result.getFirst().path());
    }

    @Test void rejectsTraversalAndDuplicates() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> WebZipPolicy.read(archive(Map.of("../escape.py", "print(1)"))));
        var entries = new LinkedHashMap<String,String>();
        entries.put("src/Test.java", "class Test {}");
        entries.put("src/test.JAVA", "class Test2 {}");
        assertThrows(IllegalArgumentException.class, () -> WebZipPolicy.read(archive(entries)));
    }

    @Test void rejectsNoSourcesOrOversizedSource() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> WebZipPolicy.read(archive(Map.of("README.md", "only readme"))));
        assertThrows(IllegalArgumentException.class, () -> WebZipPolicy.read(archive(Map.of("src/a.py", "x".repeat(270000)))));
    }
}
