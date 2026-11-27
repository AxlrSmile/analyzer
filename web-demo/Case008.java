package benchmark.cases;
import java.sql.*;
public class Case008 {
    public ResultSet find(Connection connection, String username) throws SQLException {
        String query = "SELECT id FROM users WHERE username = '" + username + "'";
        return connection.createStatement().executeQuery(query);
    }
}
