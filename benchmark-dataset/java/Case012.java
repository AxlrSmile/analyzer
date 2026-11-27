package benchmark.cases;
import java.security.SecureRandom;
import java.util.HexFormat;
public class Case012 {
    private final SecureRandom random = new SecureRandom();
    public String resetToken() {
        byte[] token = new byte[32];
        random.nextBytes(token);
        return HexFormat.of().formatHex(token);
    }
}
