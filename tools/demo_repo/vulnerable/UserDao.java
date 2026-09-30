package demo.data;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserDao {

    private final Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByRequest(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        Statement statement = connection.createStatement();
        return statement.executeQuery(query);
    }
}
