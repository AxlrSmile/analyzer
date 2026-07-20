package com.analyzer.service.scanner;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service // Регистрируем сервис в контейнере Spring
public class ProjectScannerImpl implements ProjectScanner {

    // Черный список папок, которые мы игнорируем (производительность и безопасность)
    private static final Set<String> IGNORED_DIRECTORIES = Set.of(
            ".git", ".idea", ".vscode", "node_modules", "target", "build", "gradle", ".gradle"
    );

    // Белый список расширений файлов исходного кода (Whitelist)
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "java", "py", "js", "ts", "cpp", "c", "cs", "go", "php", "rb"
    );

    @Override
    public List<File> scanDirectory(File projectDir) throws IOException {
        if (projectDir == null || !projectDir.exists() || !projectDir.isDirectory()) {
            throw new IllegalArgumentException("Предоставленный путь не является валидной директорией");
        }

        Path startPath = projectDir.toPath();

        // Открываем NIO-поток для обхода дерева файлов
        try (Stream<Path> stream = Files.walk(startPath)) {
            return stream
                    .filter(Files::isRegularFile) // Берем только файлы (исключаем папки)
                    .filter(path -> !isIgnored(path, startPath)) // Фильтруем служебные папки
                    .filter(this::isCodeFile) // Фильтруем по расширению
                    .map(Path::toFile) // Преобразуем Path в стандартный java.io.File
                    .collect(Collectors.toList());
        }
    }

    /**
     * Проверяет, находится ли файл внутри игнорируемой директории.
     */
    private boolean isIgnored(Path path, Path startPath) {
        // Получаем относительный путь от корня сканирования
        Path relativePath = startPath.relativize(path);

        // Проверяем каждый элемент пути (папку) на вхождение в черный список
        for (Path element : relativePath) {
            if (IGNORED_DIRECTORIES.contains(element.toString())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверяет, имеет ли файл разрешенное расширение исходного кода.
     */
    private boolean isCodeFile(Path path) {
        String fileName = path.getFileName().toString();
        int lastDotIndex = fileName.lastIndexOf('.');

        if (lastDotIndex == -1 || lastDotIndex == fileName.length() - 1) {
            return false; // Файл без расширения или точка в самом конце
        }

        String extension = fileName.substring(lastDotIndex + 1).toLowerCase();
        return ALLOWED_EXTENSIONS.contains(extension);
    }
}