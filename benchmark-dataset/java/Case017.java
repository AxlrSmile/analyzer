package benchmark.cases;
import java.io.IOException;
import java.nio.file.*;
public class Case017 {
    public String load(Path base, String requested) throws IOException {
        Path realBase = base.toRealPath();
        Path file = realBase.resolve(requested).toRealPath();
        if (!file.startsWith(realBase) || !Files.isRegularFile(file)) {
            throw new SecurityException("Invalid path");
        }
        return Files.readString(file);
    }
}
