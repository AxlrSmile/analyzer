package com.analyzerweb;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WebFixPolicyTest {
    private WebFixService.FindingInput finding() {
        return new WebFixService.FindingInput("LLM", "SQL-инъекция", "HIGH",
                "CWE-89", "2", "Подозрение на конкатенацию", "Проверить PreparedStatement");
    }
    private WebFixService.PreviewRequest input(String name, String source) {
        return new WebFixService.PreviewRequest(name, source, "qwen2.5-coder:7b", finding());
    }
    @Test void acceptsJavaSourceFromZipFolder() {
        var checked = WebFixPolicy.check(input("benchmark/Case008.java", "class Case008 {\n}\n"));
        assertEquals("Case008.java", checked.simpleName());
    }
    @Test void rejectsNonJavaFixPreview() {
        assertThrows(IllegalArgumentException.class,
                () -> WebFixPolicy.check(input("main.py", "print(1)\nprint(2)")));
    }
    @Test void rejectsParentTraversal() {
        assertThrows(IllegalArgumentException.class,
                () -> WebFixPolicy.check(input("../Case008.java", "class A {\n}\n")));
    }
    @Test void rejectsOutOfBoundsFinding() {
        assertThrows(IllegalArgumentException.class,
                () -> WebFixPolicy.check(input("Case008.java", "class A {}")));
    }
    @Test void rejectsBlankSource() {
        assertThrows(IllegalArgumentException.class,
                () -> WebFixPolicy.check(input("Case008.java", "")));
    }
}
