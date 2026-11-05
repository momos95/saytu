import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;

class Samples {
    void sql(Connection c, Statement st, String name, int id) throws Exception {
        // ruleid: saytu.java.sql-injection-concatenation
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: saytu.java.sql-injection-concatenation
        c.prepareStatement("DELETE FROM t WHERE id = " + id);
        // ruleid: saytu.java.sql-injection-concatenation
        st.execute(String.format("UPDATE t SET a = '%s'", name));
        // ok: saytu.java.sql-injection-concatenation
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        // ok: saytu.java.sql-injection-concatenation
        st.executeQuery("SELECT * FROM a " + "WHERE b = 1");
    }

    void sqlVariable(Statement st, String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: saytu.java.sql-injection-concatenation
        st.executeQuery(sql);
    }

    void cmd(String file) throws Exception {
        // ruleid: saytu.java.command-injection
        Runtime.getRuntime().exec("convert " + file + " out.png");
        // ruleid: saytu.java.command-injection
        new ProcessBuilder("/bin/sh", "-c", file).start();
        // ok: saytu.java.command-injection
        new ProcessBuilder("/usr/bin/convert", file, "out.png").start();
    }

    void hash() throws Exception {
        // ruleid: saytu.java.weak-hash
        MessageDigest.getInstance("MD5");
        // ruleid: saytu.java.weak-hash
        MessageDigest.getInstance("SHA-1");
        // ok: saytu.java.weak-hash
        MessageDigest.getInstance("SHA-256");
    }

    void cipher() throws Exception {
        // ruleid: saytu.java.weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: saytu.java.weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: saytu.java.weak-cipher
        Cipher.getInstance("AES");
        // ok: saytu.java.weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ruleid: saytu.java.tls-trust-all
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    void verifier(HttpsURLConnection conn) {
        // ruleid: saytu.java.tls-trust-all
        conn.setHostnameVerifier((String h, SSLSession s) -> true);
    }

    void xml() throws Exception {
        // ruleid: saytu.java.xxe-document-builder
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.newDocumentBuilder();
    }

    void xmlSafe() throws Exception {
        // ok: saytu.java.xxe-document-builder
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.newDocumentBuilder();
    }

    Object deser(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: saytu.java.unsafe-deserialization
        return ois.readObject();
    }

    Object deserFiltered(InputStream in, ObjectInputFilter filter) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(filter);
        // ok: saytu.java.unsafe-deserialization
        return ois.readObject();
    }

    void db(String pwd) throws Exception {
        // ruleid: saytu.java.hardcoded-db-password
        DriverManager.getConnection("jdbc:postgresql://db/app", "app", "S3cr3t!");
        // ok: saytu.java.hardcoded-db-password
        DriverManager.getConnection("jdbc:postgresql://db/app", "app", pwd);
    }
}
