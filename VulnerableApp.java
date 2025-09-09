:脆弱性テストコード:VulnerableApp.java
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

// このクラスは意図的に複数の脆弱性を含んでいます。
// This class is intentionally vulnerable for testing purposes.
public class VulnerableApp {

    // (1) SQLインジェクションの脆弱性
    // Vulnerability: SQL Injection
    public void getUserData(String userId) throws SQLException {
        // ユーザー入力が直接クエリに連結されている
        // User input is directly concatenated into the query.
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
        PreparedStatement stmt = conn.prepareStatement(query);
        ResultSet rs = stmt.executeQuery();
        // ...
        conn.close();
    }

    // (2) OSコマンドインジェクションの脆弱性
    // Vulnerability: OS Command Injection
    public void executeCommand(String command) throws IOException {
        // ユーザー入力がOSコマンドとして直接実行される
        // User input is directly executed as an OS command.
        Runtime.getRuntime().exec(command);
    }

    // (3) 安全でないデシリアライゼーションの脆弱性
    // Vulnerability: Insecure Deserialization
    public void deserializeObject(String filename) throws IOException, ClassNotFoundException {
        // 信頼できない入力がデシリアライズされる
        // Untrusted input is deserialized.
        try (FileInputStream fis = new FileInputStream(filename);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            ois.readObject();
        }
    }

    // (4) 危険なファイルアップロードの脆弱性 (ディレクトリトラバーサル)
    // Vulnerability: Dangerous File Upload (Directory Traversal)
    public void uploadFile(String filename, byte[] content) throws IOException {
        // ファイルパスのチェックが不十分
        // Insufficient validation of the file path.
        String uploadDir = "/var/www/uploads/";
        File file = new File(uploadDir + filename);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
    }

    // (5) ハードコードされたパスワード
    // Vulnerability: Hard-coded Password
    public void connectToDatabase() throws SQLException {
        // パスワードがソースコードに直接書かれている
        // The password is hard-coded in the source.
        String password = "mysecretpassword123";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "user", password);
        // ...
        conn.close();
    }
    
    // シリアライズ可能なクラス（デシリアライゼーションの例に必要）
    // A serializable class (needed for the deserialization example).
    static class User implements Serializable {
        private static final long serialVersionUID = 1L;
        private String username;
        public String getUsername() {
            return username;
        }
    }
}