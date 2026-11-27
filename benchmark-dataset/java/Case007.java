package benchmark.cases;
import java.io.IOException;
public class Case007 {
    public Process format(String text) throws IOException {
        return new ProcessBuilder("printf", "%s", text).start();
    }
}
