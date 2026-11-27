package com.analyzerweb;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class WebUploadPolicyTest {
    @Test void acceptsSupportedLanguagesAndUnicodeNames() {
        assertEquals("Case008.java", WebUploadPolicy.checkedName("Case008.java"));
        assertEquals("first ex (golang).go", WebUploadPolicy.checkedName("first ex (golang).go"));
        assertEquals("пример.py", WebUploadPolicy.checkedName("пример.py"));
    }

    @Test void rejectsTraversalAndUnsupportedExtensions() {
        for (String name : new String[]{"../secret.py", "..\\secret.java", "a/b.js",
                "report.pdf", "readme", ".hidden.py", "CON.java", "a..b.js"}) {
            assertThrows(IllegalArgumentException.class, () -> WebUploadPolicy.checkedName(name), name);
        }
    }

    @Test void checksBinaryOversizedAndExcessivelyLongInput() {
        assertDoesNotThrow(() -> WebUploadPolicy.checkBytes("print('Hello')\n".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> WebUploadPolicy.checkBytes(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> WebUploadPolicy.checkBytes(new byte[]{'x', 0, 'y'}));
        assertThrows(IllegalArgumentException.class, () -> WebUploadPolicy.checkBytes(new byte[WebUploadPolicy.MAX_FILE_BYTES + 1]));
        assertThrows(IllegalArgumentException.class, () -> WebUploadPolicy.checkBytes("line\n".repeat(501).getBytes(StandardCharsets.UTF_8)));
    }
}
