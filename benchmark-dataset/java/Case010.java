package benchmark.cases;
import java.io.IOException;
public class Case010 {
    public Process format(String text) throws IOException {
        return new ProcessBuilder("sh", "-c", "echo " + text).start();
    }
}
