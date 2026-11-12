package benchmark.cases;
import java.io.*;
import java.nio.charset.StandardCharsets;
public class Case003 {
    public String decode(InputStream input) throws IOException {
        byte[] data = input.readNBytes(4096);
        return new String(data, StandardCharsets.UTF_8);
    }
}
