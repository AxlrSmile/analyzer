package benchmark.cases;
import java.sql.*;
public class Case011 {
    public ResultSet find(Connection connection, String username) throws SQLException {
        PreparedStatement statement = connection.prepareStatement("SELECT id FROM users WHERE username = ?");
        statement.setString(1, username);
        return statement.executeQuery();
    }
}
