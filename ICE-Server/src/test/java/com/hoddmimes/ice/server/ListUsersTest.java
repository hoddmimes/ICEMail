package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class ListUsersTest {

    public static void main(String[] args) {
        String dbFile = args.length > 0 ? args[0] : "./ICEMail.sqlite";

        DBBase db = new DBSqlite3(dbFile);
        db.connect();

        try {
            JsonArray users = db.findAllUsers();
            if (users == null || users.isEmpty()) {
                System.out.println("No users found");
                return;
            }

            System.out.printf("%-20s %-40s %-10s %-20s %s%n", "Username", "Password", "Confirmed", "LastSeen", "Created");
            System.out.println("-".repeat(120));

            for (int i = 0; i < users.size(); i++) {
                JsonObject user = users.get(i).getAsJsonObject();
                String username = user.get(Profile.USERNAME).getAsString();
                String password = user.has(Profile.PASSWORD) ? user.get(Profile.PASSWORD).getAsString() : "N/A";
                String confirmed = user.has(Profile.CONFIRMED) ? String.valueOf(user.get(Profile.CONFIRMED).getAsBoolean()) : "N/A";
                String lastSeen = user.has(Profile.LAST_SEEN) ? user.get(Profile.LAST_SEEN).getAsString() : "N/A";
                String created = user.has(Profile.CREATED) ? user.get(Profile.CREATED).getAsString() : "N/A";
                System.out.printf("%-20s %-40s %-10s %-20s %s%n", username, password, confirmed, lastSeen, created);
            }

            System.out.println("-".repeat(120));
            System.out.println("Total: " + users.size() + " users");

        } catch (DBException e) {
            System.err.println("Database error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            db.close();
        }
    }
}
