package com.hoddmimes.ice.server.web;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hoddmimes.ice.server.DBException;
import com.hoddmimes.ice.server.DBSqlite3;
import com.hoddmimes.ice.server.JAux;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.javalin.http.Context;

public class ContactHandler {

    private static final Logger LOGGER = LogManager.getLogger(ContactHandler.class);

    private final DBSqlite3 mDb;

    public ContactHandler(DBSqlite3 db) {
        this.mDb = db;
    }

    private String getUsername(Context ctx) {
        JsonObject jUser = (JsonObject) ctx.req().getSession().getAttribute("username");
        if (jUser == null || !jUser.has("username")) {
            return null;
        }
        return jUser.get("username").getAsString();
    }

    public void listContacts(Context ctx) {
        String username = getUsername(ctx);
        if (username == null) {
            ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
            return;
        }

        try {
            JsonArray contacts = mDb.findContacts(username);
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(contacts));
        } catch (DBException e) {
            LOGGER.warn("Failed to list contacts for {}: {}", username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve contacts"));
        }
    }

    public void createContact(Context ctx) {
        String username = getUsername(ctx);
        if (username == null) {
            ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
            return;
        }

        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();
        if (!jBody.has("name") || !jBody.has("email")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing required parameters: name and email"));
            return;
        }

        String name = jBody.get("name").getAsString().trim();
        String email = jBody.get("email").getAsString().trim();

        if (name.isEmpty() || email.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Name and email must not be empty"));
            return;
        }

        try {
            mDb.createContact(username, name, email);
            ctx.status(200).result(JAux.statusResponse(200, "Contact created"));
        } catch (DBException e) {
            LOGGER.warn("Failed to create contact for {}: {}", username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to create contact"));
        }
    }

    public void updateContact(Context ctx) {
        String username = getUsername(ctx);
        if (username == null) {
            ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
            return;
        }

        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();
        if (!jBody.has("id") || !jBody.has("name") || !jBody.has("email")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing required parameters: id, name, and email"));
            return;
        }

        int id = jBody.get("id").getAsInt();
        String name = jBody.get("name").getAsString().trim();
        String email = jBody.get("email").getAsString().trim();

        if (name.isEmpty() || email.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Name and email must not be empty"));
            return;
        }

        try {
            mDb.updateContact(username, id, name, email);
            ctx.status(200).result(JAux.statusResponse(200, "Contact updated"));
        } catch (DBException e) {
            LOGGER.warn("Failed to update contact for {}: {}", username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to update contact"));
        }
    }

    public void deleteContact(Context ctx) {
        String username = getUsername(ctx);
        if (username == null) {
            ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
            return;
        }

        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();
        if (!jBody.has("id")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing required parameter: id"));
            return;
        }

        int id = jBody.get("id").getAsInt();

        try {
            mDb.deleteContact(username, id);
            ctx.status(200).result(JAux.statusResponse(200, "Contact deleted"));
        } catch (DBException e) {
            LOGGER.warn("Failed to delete contact for {}: {}", username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to delete contact"));
        }
    }
}
