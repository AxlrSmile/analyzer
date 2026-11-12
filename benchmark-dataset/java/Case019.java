package benchmark.cases;
import java.util.Random;
public class Case019 {
    private final Random random = new Random();
    public String resetToken() {
        return Long.toHexString(random.nextLong());
    }
}
