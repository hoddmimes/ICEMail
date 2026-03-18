package com.hoddmimes.ice.server.admin;

import com.google.gson.JsonObject;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ImapRestApi {
    private static final Logger LOGGER = LogManager.getLogger(ImapRestApi.class);

    private JsonObject jConfig;
    private final String mBaseUrl;
    private String mAdminPassword = null;


    public ImapRestApi(JsonObject pConfiguration) {
        jConfig = pConfiguration;
        mBaseUrl = "http://" + jConfig.get("imap_host").getAsString() + ":" + jConfig.get("imap_restapi_port").getAsInt();
        if (jConfig.has("admin")) {
            JsonObject jAdmin = jConfig.get("admin").getAsJsonObject();
            if (jAdmin.has("password")) {
                mAdminPassword = jAdmin.get("password").getAsString();
            }
        }
    }

    public String getUsers() {
        return doGet("/users");
    }

    public String getDomains() {
        return doGet("/domains");
    }

    public String getUserMailboxes(String userName) {
        return doGet("/users/" + URLEncoder.encode(userName, StandardCharsets.UTF_8) + "/mailboxes");
    }

    public boolean addUser(String username, String password) {
        try {
            URL url = new URI(mBaseUrl + "/users/" + URLEncoder.encode(username, StandardCharsets.UTF_8)).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("PUT");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            if (mAdminPassword != null) {
                String auth = Base64.getEncoder().encodeToString(("admin:" + mAdminPassword).getBytes(StandardCharsets.UTF_8));
                connection.setRequestProperty("Authorization", "Basic " + auth);
            }
            String body = "{\"password\":\"" + password + "\"}";
            connection.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));

            int statusCode = connection.getResponseCode();
            if (statusCode >= 200 && statusCode < 300) {
                LOGGER.info("IMAP user created for \"{}\"", username);
                return true;
            } else {
                LOGGER.warn("IMAP addUser \"{}\" failed, status: {}", username, statusCode);
                return false;
            }
        } catch (Exception e) {
            LOGGER.warn("IMAP addUser \"{}\" failed, reason: {}", username, e.getMessage());
            return false;
        }
    }

    public String getMailQueues() {
        return doGet("/mailQueues");
    }

    public String getMailRepositories() {
        return doGet("/mailRepositories");
    }

    public String getDeadLetterGroups() {
        return doGet("/events/deadLetter/groups");
    }

    private String doGet(String pPath) {
        try {
            URL url = new URI(mBaseUrl + pPath).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            if (mAdminPassword != null) {
                String auth = Base64.getEncoder().encodeToString(("admin:" + mAdminPassword).getBytes(StandardCharsets.UTF_8));
                connection.setRequestProperty("Authorization", "Basic " + auth);
            }

            int statusCode = connection.getResponseCode();
            InputStream inputStream = (statusCode >= 200 && statusCode < 300) ?
                    connection.getInputStream() : connection.getErrorStream();

            StringBuilder responseBuilder = new StringBuilder();
            if (inputStream != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    String responseLine;
                    while ((responseLine = reader.readLine()) != null) {
                        responseBuilder.append(responseLine);
                    }
                }
            }

            if (statusCode >= 200 && statusCode < 300) {
                return responseBuilder.toString();
            } else {
                LOGGER.warn("IMAP REST API GET {} failed, status: {} reason: {}", pPath, statusCode, responseBuilder);
                return null;
            }
        } catch (Exception e) {
            LOGGER.warn("IMAP REST API GET {} failed, reason: {}", pPath, e.getMessage());
            return null;
        }
    }


}
