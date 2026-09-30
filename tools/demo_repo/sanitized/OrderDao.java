package demo.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class OrderDao {

    private final Connection connection;

    public OrderDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByRequest(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement statement =
                connection.prepareStatement("SELECT * FROM orders WHERE id = ?");
        statement.setString(1, id);
        return statement.executeQuery();
    }
}
