package benchmark.cases;
import java.io.IOException;
import java.nio.file.*;
public class Case002 {
    public String load(Path base, String requested) throws IOException {
        Path file = base.resolve(requested);
        return Files.readString(file);
    }
}
