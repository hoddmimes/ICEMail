package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.text.SimpleDateFormat;

public class DBSqlite3Test {
    
    private final DBSqlite3 db;
    private final String dbFile;

    public DBSqlite3Test(String dbFilename) {
        this.dbFile = dbFilename;
        this.db = new DBSqlite3(dbFilename);
    }

    private JsonObject generateUserProfile(String pUsername) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

        JsonObject jUser = new JsonObject();
        jUser.addProperty(Profile.USERNAME, pUsername);
        jUser.addProperty(Profile.PASSWORD, FakeWords.generateWord(12));
        jUser.addProperty(Profile.PRIVATE_KEY, FakeWords.generateString(24));
        jUser.addProperty(Profile.PUBLIC_KEY, FakeWords.generateString(24));
        jUser.addProperty(Profile.LAST_SEEN, sdf.format(System.currentTimeMillis()));
        jUser.addProperty(Profile.CONFIRMATION_MAIL, pUsername + "@foobar.com");
        jUser.addProperty(Profile.CONFIRMED, false);
        jUser.addProperty(Profile.CREATED, sdf.format(System.currentTimeMillis()));

        return jUser;
    }

    private void testCreateUsers() throws DBException {
        System.out.println("\n=== Testing User Creation ===");
        
        db.createUser(generateUserProfile("Liam"));
        db.createUser(generateUserProfile("Joshua"));
        db.createUser(generateUserProfile("Bob"));
        db.createUser(generateUserProfile("Alice"));
        db.createUser(generateUserProfile("Jack"));
        db.createUser(generateUserProfile("Lucas"));
        
        System.out.println("Created 6 test users");
    }

    private void testFindUser(String pUsername) throws DBException {
        System.out.println("\n=== Testing Find User: " + pUsername + " ===");
        
        JsonObject jObj = db.findUser(pUsername);
        if (jObj != null) {
            System.out.println("Found user: " + jObj);
        } else {
            System.out.println("User '" + pUsername + "' not found");
        }
    }

    private void testFindAllUsers() throws DBException {
        System.out.println("\n=== Testing Find All Users ===");
        
        JsonArray jArr = db.findAllUsers();
        if (jArr == null) {
            System.out.println("No users found");
        } else {
            System.out.println("Found " + jArr.size() + " users:");
            for (int i = 0; i < jArr.size(); i++) {
                System.out.println("  " + jArr.get(i).toString());
            }
        }
    }

    private void testUserExists(String pUsername) throws DBException {
        System.out.println("\n=== Testing User Exists: " + pUsername + " ===");
        
        boolean exists = db.ifUserExists(pUsername);
        System.out.println("User '" + pUsername + "' exists: " + exists);
    }

    private void testUpdateUser() throws DBException {
        System.out.println("\n=== Testing Update User ===");
        
        JsonObject jUser = db.findUser("Alice");
        if (jUser != null) {
            System.out.println("Before update: " + jUser.get("confirmed"));
            

            
            db.updateLastSeen("Alice");
            
            jUser = db.findUser("Alice");
            System.out.println("After update: " + jUser.get(Profile.LAST_SEEN));
        }
    }

    private void testDeleteUser(String pUsername) throws DBException {
        System.out.println("\n=== Testing Delete User: " + pUsername + " ===");
        
        boolean existsBefore = db.ifUserExists(pUsername);
        System.out.println("User exists before delete: " + existsBefore);
        
        if (existsBefore) {
            db.deleteUser(pUsername);
            boolean existsAfter = db.ifUserExists(pUsername);
            System.out.println("User exists after delete: " + existsAfter);
        }
    }

    private void testUpdateLastSeen(String pUsername) throws DBException {
        System.out.println("\n=== Testing Update Last Seen: " + pUsername + " ===");
        
        JsonObject jUser = db.findUser(pUsername);
        if (jUser != null) {
            System.out.println("Last seen before: " + jUser.get(Profile.LAST_SEEN));
            
            // Wait a bit to see time difference
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            
            db.updateLastSeen(pUsername);
            
            JsonObject jUpdated = db.findUser(pUsername);
            System.out.println("Last seen after: " + jUpdated.get(Profile.LAST_SEEN));
        }
    }

    public void runAllTests() {
        System.out.println("===================================");
        System.out.println("Starting DBSqlite3 Test Suite");
        System.out.println("===================================");

        // Delete existing database file
        File tFile = new File(dbFile);
        if (tFile.exists()) {
            tFile.delete();
            System.out.println("Deleted existing database file");
        }

        // Connect to database (will create new one)
        db.connect();
        System.out.println("Connected to database: " + dbFile);

        try {
            // Run tests
            testCreateUsers();
            testFindAllUsers();
            testFindUser("Lucas");
            testFindUser("Frotz");
            testUserExists("Alice");
            testUserExists("NonExistent");
            testUpdateLastSeen("Bob");
            testDeleteUser("Alice");
            testFindAllUsers();

            System.out.println("\n=== All Tests Completed Successfully ===");

        } catch (DBException e) {
            System.err.println("\n=== Test Failed ===");
            e.printStackTrace();
        } finally {
            db.close();
            System.out.println("\nDatabase connection closed");
        }

        // Reopen database to verify persistence
        System.out.println("\n=== Testing Database Persistence ===");
        db.connect();
        
        try {
            testFindAllUsers();
            testFindUser("Alice");
        } catch (DBException e) {
            e.printStackTrace();
        } finally {
            db.close();
        }

        System.out.println("\n===================================");
        System.out.println("Test Suite Complete");
        System.out.println("===================================");
    }

    public static void main(String[] args) {
        DBSqlite3Test test = new DBSqlite3Test("./icemail-test.db");
        test.runAllTests();
    }
}