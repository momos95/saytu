package demo;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/** Deliberately vulnerable code used by SAYTU's scanner tests. */
public class UserRepository {

    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByName(String name) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public byte[] legacyHash(byte[] password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password);
    }
}
