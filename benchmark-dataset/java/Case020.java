package benchmark.cases;
import java.io.*;
public class Case020 {
    public Object decode(InputStream input) throws IOException, ClassNotFoundException {
        try (ObjectInputStream stream = new ObjectInputStream(input)) {
            return stream.readObject();
        }
    }
}
