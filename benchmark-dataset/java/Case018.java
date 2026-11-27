package benchmark.cases;
import java.util.logging.Logger;
public class Case018 {
    private static final Logger LOG = Logger.getLogger(Case018.class.getName());
    public void login(String user, String password) {
        LOG.info("Login request received");
    }
}
