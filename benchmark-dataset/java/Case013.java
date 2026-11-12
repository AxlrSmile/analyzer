package benchmark.cases;
import java.util.logging.Logger;
public class Case013 {
    private static final Logger LOG = Logger.getLogger(Case013.class.getName());
    public void login(String user, String password) {
        LOG.info("Login attempt user=" + user + " password=" + password);
    }
}
