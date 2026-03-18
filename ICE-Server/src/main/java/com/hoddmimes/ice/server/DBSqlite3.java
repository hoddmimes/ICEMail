package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.sqlite.SQLiteConfig;

import java.io.File;
import java.sql.*;
import java.text.SimpleDateFormat;

public class DBSqlite3 implements DBBase
{
    private static final String DB_TABLE_PROFILE = "profiles";
    private static final String DB_TABLE_CONTACTS = "contacts";
    private static final String DB_TABLE_DECRYPT_MESSAGES = "decrypt_messages";


    private static final String SQL_SAVE_PROFILE =
            "INSERT INTO " + DB_TABLE_PROFILE + " (" +
                    Profile.USERNAME + "," +
                    Profile.PASSWORD + "," +
                    Profile.PRIVATE_KEY + "," +
                    Profile.PUBLIC_KEY + "," +
                    Profile.LAST_SEEN + "," +
                    Profile.CONFIRMATION_MAIL + "," +
                    Profile.CONFIRMED + ", " +
                    Profile.CREATED + ", " +
                    Profile.BLOCKED + ", " +
                    Profile.MAILBOX + ", " +
                    Profile.CONF_UID + ") " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)";

    private static final String SQL_FIND_USER =
            "SELECT * FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.USERNAME + " = ?";

    private static final String SQL_FIND_ALL_USERS =
            "SELECT * FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.CONFIRMED + " = 1";

    private static final String SQL_UPDATE_USER_LAST_SEEN =
            "UPDATE " + DB_TABLE_PROFILE + " SET " +
                    Profile.LAST_SEEN + " = ?, " +
                    "WHERE " + Profile.USERNAME + " = ?";

    private static final String SQL_DELETE_USER =
            "DELETE FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.USERNAME + " = ?";

    private final String mSqlFile;
    private Connection mConnection = null;

    public DBSqlite3(String dbFilename) {
        mSqlFile = dbFilename;
    }

    @Override
    public void connect() {
        try {
            File tFile = new File(mSqlFile);
            if (!tFile.exists() || (!tFile.canRead())) {
                createDatabase();
            }
            openDatabase();
            ensureContactsTable();
            ensureConfUidColumn();
            ensureDecryptMessagesTable();
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    private void ensureContactsTable() throws DBException {
        String sqlStmtContacts = "CREATE TABLE IF NOT EXISTS " + DB_TABLE_CONTACTS +
                " (id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "username TEXT NOT NULL," +
                "name TEXT NOT NULL," +
                "email TEXT NOT NULL);";

        String sqlStmtContactsIndex = "CREATE INDEX IF NOT EXISTS index_" + DB_TABLE_CONTACTS +
                " ON " + DB_TABLE_CONTACTS + " (username);";

        try (Statement stmt = mConnection.createStatement()) {
            stmt.execute(sqlStmtContacts);
            stmt.execute(sqlStmtContactsIndex);
        } catch (SQLException e) {
            throw new DBException("Failed to create contacts table", e);
        }
    }

    private void ensureConfUidColumn() throws DBException {
        try (Statement stmt = mConnection.createStatement()) {
            ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + DB_TABLE_PROFILE + ")");
            boolean hasConfUid = false;
            while (rs.next()) {
                if (Profile.CONF_UID.equals(rs.getString("name"))) {
                    hasConfUid = true;
                    break;
                }
            }
            if (!hasConfUid) {
                stmt.execute("ALTER TABLE " + DB_TABLE_PROFILE + " ADD COLUMN " + Profile.CONF_UID + " TEXT");
            }
        } catch (SQLException e) {
            throw new DBException("Failed to ensure confUid column", e);
        }
    }

    private void createDatabase() throws DBException {
        String url = "jdbc:sqlite:" + mSqlFile;

        try {
            mConnection = DriverManager.getConnection(url);
            if (mConnection != null) {
                createCollectionTable();
                mConnection.close();
            }
        } catch (SQLException e) {
            throw new DBException("Failed to create database", e);
        }
    }

    private void createCollectionTable() throws DBException {
        String sqlStmtProfile = "CREATE TABLE IF NOT EXISTS " + DB_TABLE_PROFILE +
                " (" + Profile.USERNAME + " TEXT PRIMARY KEY," +
                Profile.PASSWORD + " TEXT NOT NULL," +
                Profile.PRIVATE_KEY + " TEXT NOT NULL, " +
                Profile.PUBLIC_KEY + " TEXT NOT NULL,  " +
                Profile.LAST_SEEN + " TEXT NOT NULL, " +
                Profile.CONFIRMATION_MAIL + " TEXT NOT NULL, " +
                Profile.CONFIRMED + " BOOLEAN NOT NULL, " +
                Profile.CREATED + " TEXT NOT NULL, " +
                Profile.BLOCKED + " BOOLEAN NOT NULL DEFAULT 0, " +
                Profile.MAILBOX + " TEXT, " +
                Profile.CONF_UID + " TEXT" +
                ");";

        String sqlStmtIndex = "CREATE INDEX IF NOT EXISTS index_" + DB_TABLE_PROFILE +
                " ON " + DB_TABLE_PROFILE + " (" + Profile.USERNAME + ");";

        String sqlStmtContacts = "CREATE TABLE IF NOT EXISTS " + DB_TABLE_CONTACTS +
                " (id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "username TEXT NOT NULL," +
                "name TEXT NOT NULL," +
                "email TEXT NOT NULL);";

        String sqlStmtContactsIndex = "CREATE INDEX IF NOT EXISTS index_" + DB_TABLE_CONTACTS +
                " ON " + DB_TABLE_CONTACTS + " (username);";

        try (Statement stmt = mConnection.createStatement()) {
            stmt.execute(sqlStmtProfile);
            stmt.execute(sqlStmtIndex);
            stmt.execute(sqlStmtContacts);
            stmt.execute(sqlStmtContactsIndex);
        } catch (SQLException e) {
            throw new DBException("Failed to create table", e);
        }
    }

    private void openDatabase() throws DBException {
        String url = "jdbc:sqlite:" + mSqlFile;

        File dbFile = new File(mSqlFile);
        if (!dbFile.exists()) {
            throw new DBException("Database file " + mSqlFile + " is not found");
        }

        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new DBException("SQLite JDBC driver not found", e);
        }

        try {
            SQLiteConfig config = new SQLiteConfig();
            config.setJournalMode(SQLiteConfig.JournalMode.WAL);
            config.setTempStore(SQLiteConfig.TempStore.DEFAULT);
            config.setSynchronous(SQLiteConfig.SynchronousMode.NORMAL);
            config.enforceForeignKeys(false);

            mConnection = DriverManager.getConnection(url, config.toProperties());
        } catch (SQLException e) {
            throw new DBException("Failed to open database", e);
        }
    }

    @Override
    public void close() {
        if (mConnection != null) {
            try {
                mConnection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public boolean ifUserExists(String pUsername) throws DBException {
        try (PreparedStatement stmt = mConnection.prepareStatement(SQL_FIND_USER)) {
            stmt.setString(1, pUsername);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new DBException("Failed to check if user exists", e);
        }
    }

    @Override
    public JsonObject findUser(String pUsername) throws DBException {
        try (PreparedStatement stmt = mConnection.prepareStatement(SQL_FIND_USER)) {
            stmt.setString(1, pUsername);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return resultSetToJsonObject(rs);
                }
                return null;
            }
        } catch (SQLException e) {
            throw new DBException("Failed to find user", e);
        }
    }

    @Override
    public JsonArray findAllUsers() throws DBException {
        JsonArray jResult = new JsonArray();

        try (Statement stmt = mConnection.createStatement();
             ResultSet rs = stmt.executeQuery(SQL_FIND_ALL_USERS)) {

            while (rs.next()) {
                JsonObject jProfile = new JsonObject();
                jProfile.addProperty(Profile.USERNAME, rs.getString(Profile.USERNAME));
                jProfile.addProperty(Profile.PASSWORD, rs.getString(Profile.PASSWORD));
                jProfile.addProperty(Profile.CREATED, rs.getString(Profile.CREATED));
                jProfile.addProperty(Profile.LAST_SEEN, rs.getString(Profile.LAST_SEEN));
                jProfile.addProperty(Profile.CONFIRMATION_MAIL, rs.getString(Profile.CONFIRMATION_MAIL));
                jProfile.addProperty(Profile.CONFIRMED, rs.getBoolean(Profile.CONFIRMED));
                jProfile.addProperty(Profile.BLOCKED, rs.getBoolean(Profile.BLOCKED));
                jResult.add(jProfile);
            }

            return jResult.size() == 0 ? null : jResult;
        } catch (SQLException e) {
            throw new DBException("Failed to find all users", e);
        }
    }

    @Override
    public JsonArray findUsers(String pFilter) throws DBException {
        if (pFilter == null || pFilter.isEmpty()) {
            return findAllUsers();
        }

        String sql = "SELECT * FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.USERNAME + " LIKE ?";
        JsonArray jResult = new JsonArray();

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, "%" + pFilter + "%");

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    JsonObject jProfile = new JsonObject();
                    jProfile.addProperty(Profile.USERNAME, rs.getString(Profile.USERNAME));
                    jProfile.addProperty(Profile.CREATED, rs.getString(Profile.CREATED));
                    jProfile.addProperty(Profile.LAST_SEEN, rs.getString(Profile.LAST_SEEN));
                    jProfile.addProperty(Profile.CONFIRMATION_MAIL, rs.getString(Profile.CONFIRMATION_MAIL));
                    jProfile.addProperty(Profile.CONFIRMED, rs.getBoolean(Profile.CONFIRMED));
                    jProfile.addProperty(Profile.BLOCKED, rs.getBoolean(Profile.BLOCKED));
                    jResult.add(jProfile);
                }
            }

            return jResult.size() == 0 ? null : jResult;
        } catch (SQLException e) {
            throw new DBException("Failed to find users with filter", e);
        }
    }

    @Override
    public JsonArray findAllUserCredentials() throws DBException {
        JsonArray jResult = new JsonArray();

        try (Statement stmt = mConnection.createStatement();
             ResultSet rs = stmt.executeQuery(SQL_FIND_ALL_USERS)) {

            while (rs.next()) {
                JsonObject jUser = new JsonObject();
                jUser.addProperty(Profile.USERNAME, rs.getString(Profile.USERNAME));
                jUser.addProperty(Profile.PASSWORD, rs.getString(Profile.PASSWORD));
                jResult.add(jUser);
            }

            return jResult;
        } catch (SQLException e) {
            throw new DBException("Failed to find all user credentials", e);
        }
    }

    @Override
    public void createUser(JsonObject jUser) throws DBException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

        try (PreparedStatement stmt = mConnection.prepareStatement(SQL_SAVE_PROFILE)) {
            stmt.setString(1, jUser.get(Profile.USERNAME).getAsString());
            stmt.setString(2, jUser.get(Profile.PASSWORD).getAsString());
            stmt.setString(3, jUser.get(Profile.PRIVATE_KEY).getAsString());
            stmt.setString(4, jUser.get(Profile.PUBLIC_KEY).getAsString());
            stmt.setString(5, sdf.format(System.currentTimeMillis()));
            stmt.setString(6, jUser.get(Profile.CONFIRMATION_MAIL).getAsString());
            stmt.setBoolean(7, jUser.get(Profile.CONFIRMED).getAsBoolean());
            stmt.setString(8, sdf.format(System.currentTimeMillis()));
            stmt.setBoolean(9, false);
            stmt.setNull(10, Types.VARCHAR);
            if (jUser.has(Profile.CONF_UID) && !jUser.get(Profile.CONF_UID).isJsonNull()) {
                stmt.setString(11, jUser.get(Profile.CONF_UID).getAsString());
            } else {
                stmt.setNull(11, Types.VARCHAR);
            }

            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new DBException("Failed to create user", e);
        }
    }


    @Override
    public void deleteUser(String pUsername) throws DBException {
        try (PreparedStatement stmt = mConnection.prepareStatement(SQL_DELETE_USER)) {
            stmt.setString(1, pUsername);

            int rowsAffected = stmt.executeUpdate();
            if (rowsAffected == 0) {
                throw new DBException("User not found: " + pUsername);
            }
        } catch (SQLException e) {
            throw new DBException("Failed to delete user", e);
        }
    }

    public void updateLastSeen(String pUsername) throws DBException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String sql = "UPDATE " + DB_TABLE_PROFILE + " SET " + Profile.LAST_SEEN + " = ? WHERE " + Profile.USERNAME + " = ?";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, sdf.format(System.currentTimeMillis()));
            stmt.setString(2, pUsername);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new DBException("Failed to update last seen", e);
        }
    }

    // ===== Contacts CRUD =====

    public JsonArray findContacts(String username) throws DBException {
        String sql = "SELECT * FROM " + DB_TABLE_CONTACTS + " WHERE username = ? ORDER BY name";
        JsonArray result = new JsonArray();

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    JsonObject contact = new JsonObject();
                    contact.addProperty("id", rs.getInt("id"));
                    contact.addProperty("name", rs.getString("name"));
                    contact.addProperty("email", rs.getString("email"));
                    result.add(contact);
                }
            }
        } catch (SQLException e) {
            throw new DBException("Failed to find contacts", e);
        }
        return result;
    }

    public void createContact(String username, String name, String email) throws DBException {
        String sql = "INSERT INTO " + DB_TABLE_CONTACTS + " (username, name, email) VALUES (?, ?, ?)";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, name);
            stmt.setString(3, email);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new DBException("Failed to create contact", e);
        }
    }

    public void updateContact(String username, int id, String name, String email) throws DBException {
        String sql = "UPDATE " + DB_TABLE_CONTACTS + " SET name = ?, email = ? WHERE id = ? AND username = ?";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, name);
            stmt.setString(2, email);
            stmt.setInt(3, id);
            stmt.setString(4, username);
            int rows = stmt.executeUpdate();
            if (rows == 0) {
                throw new DBException("Contact not found");
            }
        } catch (SQLException e) {
            throw new DBException("Failed to update contact", e);
        }
    }

    public void deleteContact(String username, int id) throws DBException {
        String sql = "DELETE FROM " + DB_TABLE_CONTACTS + " WHERE id = ? AND username = ?";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.setString(2, username);
            int rows = stmt.executeUpdate();
            if (rows == 0) {
                throw new DBException("Contact not found");
            }
        } catch (SQLException e) {
            throw new DBException("Failed to delete contact", e);
        }
    }

    public JsonObject findUserByConfUid(String confUid) throws DBException {
        String sql = "SELECT * FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.CONF_UID + " = ?";
        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, confUid);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return resultSetToJsonObject(rs);
                }
                return null;
            }
        } catch (SQLException e) {
            throw new DBException("Failed to find user by confUid", e);
        }
    }

    public void confirmUser(String confUid) throws DBException {
        String sql = "UPDATE " + DB_TABLE_PROFILE + " SET " + Profile.CONFIRMED + " = 1, " +
                Profile.CONF_UID + " = NULL WHERE " + Profile.CONF_UID + " = ?";
        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, confUid);
            int rows = stmt.executeUpdate();
            if (rows == 0) {
                throw new DBException("No user found with confUid: " + confUid);
            }
        } catch (SQLException e) {
            throw new DBException("Failed to confirm user", e);
        }
    }

    public void updatePassword(String username, String newHashedPassword, String newPrivateKey) throws DBException {
        String sql = "UPDATE " + DB_TABLE_PROFILE + " SET " +
                Profile.PASSWORD + " = ?, " +
                Profile.PRIVATE_KEY + " = ? WHERE " + Profile.USERNAME + " = ?";
        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, newHashedPassword);
            stmt.setString(2, newPrivateKey);
            stmt.setString(3, username);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new DBException("Failed to update password", e);
        }
    }

    public void confirmUserByUsername(String username) throws DBException {
        String sql = "UPDATE " + DB_TABLE_PROFILE + " SET " + Profile.CONFIRMED + " = 1, " +
                Profile.CONF_UID + " = NULL WHERE " + Profile.USERNAME + " = ?";
        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, username);
            int rows = stmt.executeUpdate();
            if (rows == 0) {
                throw new DBException("No user found with username: " + username);
            }
        } catch (SQLException e) {
            throw new DBException("Failed to confirm user", e);
        }
    }

    @Override
    public int countProfiles() throws DBException {
        String sql = "SELECT COUNT(*) FROM " + DB_TABLE_PROFILE;
        try (Statement stmt = mConnection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new DBException("Failed to count profiles", e);
        }
    }

    @Override
    public int countActiveUsersLast24h() throws DBException {
        String sql = "SELECT COUNT(*) FROM " + DB_TABLE_PROFILE +
                " WHERE " + Profile.LAST_SEEN + " > datetime('now', '-24 hours')";
        try (Statement stmt = mConnection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new DBException("Failed to count active users last 24h", e);
        }
    }

    private void ensureDecryptMessagesTable() throws DBException {
        String sql = "CREATE TABLE IF NOT EXISTS " + DB_TABLE_DECRYPT_MESSAGES +
                " (uid TEXT PRIMARY KEY," +
                "encrypted_body TEXT NOT NULL," +
                "sender TEXT," +
                "created TEXT NOT NULL," +
                "attachments TEXT);";

        try (Statement stmt = mConnection.createStatement()) {
            stmt.execute(sql);
            // Migrate existing tables that lack the attachments column
            ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + DB_TABLE_DECRYPT_MESSAGES + ")");
            boolean hasAttachments = false;
            while (rs.next()) {
                if ("attachments".equals(rs.getString("name"))) {
                    hasAttachments = true;
                    break;
                }
            }
            if (!hasAttachments) {
                stmt.execute("ALTER TABLE " + DB_TABLE_DECRYPT_MESSAGES + " ADD COLUMN attachments TEXT");
            }
        } catch (SQLException e) {
            throw new DBException("Failed to create decrypt_messages table", e);
        }
    }

    @Override
    public void saveDecryptMessage(String uid, String encryptedBody, String sender, String attachmentsJson) throws DBException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String sql = "INSERT INTO " + DB_TABLE_DECRYPT_MESSAGES + " (uid, encrypted_body, sender, created, attachments) VALUES (?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, uid);
            stmt.setString(2, encryptedBody);
            stmt.setString(3, sender);
            stmt.setString(4, sdf.format(System.currentTimeMillis()));
            if (attachmentsJson != null) {
                stmt.setString(5, attachmentsJson);
            } else {
                stmt.setNull(5, Types.VARCHAR);
            }
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new DBException("Failed to save decrypt message", e);
        }
    }

    @Override
    public JsonObject findDecryptMessage(String uid) throws DBException {
        String sql = "SELECT * FROM " + DB_TABLE_DECRYPT_MESSAGES + " WHERE uid = ?";

        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, uid);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    JsonObject result = new JsonObject();
                    result.addProperty("uid", rs.getString("uid"));
                    result.addProperty("encrypted_body", rs.getString("encrypted_body"));
                    result.addProperty("sender", rs.getString("sender"));
                    result.addProperty("created", rs.getString("created"));
                    String attachments = rs.getString("attachments");
                    if (attachments != null) {
                        result.addProperty("attachments", attachments);
                    }
                    return result;
                }
                return null;
            }
        } catch (SQLException e) {
            throw new DBException("Failed to find decrypt message", e);
        }
    }

    @Override
    public int deleteExpiredDecryptMessages(int ttlHours) throws DBException {
        String sql = "DELETE FROM " + DB_TABLE_DECRYPT_MESSAGES +
                " WHERE created < datetime('now', '-" + ttlHours + " hours')";
        try (Statement stmt = mConnection.createStatement()) {
            return stmt.executeUpdate(sql);
        } catch (SQLException e) {
            throw new DBException("Failed to delete expired decrypt messages", e);
        }
    }

    @Override
    public String findUserPublicKey(String username) throws DBException {
        String sql = "SELECT " + Profile.PUBLIC_KEY + " FROM " + DB_TABLE_PROFILE + " WHERE " + Profile.USERNAME + " = ?";
        try (PreparedStatement stmt = mConnection.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(Profile.PUBLIC_KEY);
                }
                return null;
            }
        } catch (SQLException e) {
            throw new DBException("Failed to find user public key", e);
        }
    }

    private JsonObject resultSetToJsonObject(ResultSet rs) throws SQLException {
        JsonObject jProfile = new JsonObject();
        jProfile.addProperty(Profile.USERNAME, rs.getString(Profile.USERNAME));
        jProfile.addProperty(Profile.PASSWORD, rs.getString(Profile.PASSWORD));
        jProfile.addProperty(Profile.PRIVATE_KEY, rs.getString(Profile.PRIVATE_KEY));
        jProfile.addProperty(Profile.PUBLIC_KEY, rs.getString(Profile.PUBLIC_KEY));
        jProfile.addProperty(Profile.LAST_SEEN, rs.getString(Profile.LAST_SEEN));
        jProfile.addProperty(Profile.CONFIRMATION_MAIL, rs.getString(Profile.CONFIRMATION_MAIL));
        jProfile.addProperty(Profile.CONFIRMED, rs.getBoolean(Profile.CONFIRMED));
        jProfile.addProperty(Profile.CREATED, rs.getString(Profile.CREATED));
        jProfile.addProperty(Profile.BLOCKED, rs.getBoolean(Profile.BLOCKED));
        String mailbox = rs.getString(Profile.MAILBOX);
        if (mailbox != null) {
            jProfile.addProperty(Profile.MAILBOX, mailbox);
        }
        return jProfile;
    }
}