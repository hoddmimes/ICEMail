package com.hoddmimes.ice.server.admin;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hoddmimes.ice.server.AltchaService;
import com.hoddmimes.ice.server.DBBase;
import com.hoddmimes.ice.server.DBException;
import com.hoddmimes.ice.server.JAux;
import com.hoddmimes.ice.server.Profile;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.javalin.http.Context;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles admin-related API endpoints for user management.
 */
public class AdminHandler {

    private static final Logger LOGGER = LogManager.getLogger(AdminHandler.class);

    private static final int MAX_REGISTRATIONS_PER_IP = 3;
    private static final long RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour

    private final DBBase mDb;
    private final String mBaseUrl;
    private final String mMailDomain;
    private final boolean mAllowRegistration;
    private final String mInternalMailUser;
    private final String mInternalMailPassword;
    private final String mSmtpHost;
    private final int mSmtpPort;
    private final boolean mSmtpStartTls;
    private final AltchaService mAltchaService;
    private final boolean mAdminNotificationsEnabled;
    private final String mAdminNotificationAddress;
    private final ConcurrentHashMap<String, LinkedList<Long>> mRegistrationAttempts = new ConcurrentHashMap<>();

    public AdminHandler(DBBase db, String baseUrl, String mailDomain, boolean allowRegistration,
                        String internalMailUser, String internalMailPassword,
                        String smtpHost, int smtpPort, boolean smtpStartTls,
                        AltchaService altchaService,
                        boolean adminNotificationsEnabled, String adminNotificationAddress) {
        this.mDb = db;
        this.mBaseUrl = baseUrl;
        this.mMailDomain = mailDomain;
        this.mAllowRegistration = allowRegistration;
        this.mInternalMailUser = internalMailUser;
        this.mInternalMailPassword = internalMailPassword;
        this.mSmtpHost = smtpHost;
        this.mSmtpPort = smtpPort;
        this.mSmtpStartTls = smtpStartTls;
        this.mAltchaService = altchaService;
        this.mAdminNotificationsEnabled = adminNotificationsEnabled;
        this.mAdminNotificationAddress = adminNotificationAddress;
    }

    private boolean isRateLimited(String ip) {
        long now = System.currentTimeMillis();
        LinkedList<Long> timestamps = mRegistrationAttempts.computeIfAbsent(ip, k -> new LinkedList<>());

        synchronized (timestamps) {
            Iterator<Long> it = timestamps.iterator();
            while (it.hasNext()) {
                if (now - it.next() > RATE_LIMIT_WINDOW_MS) {
                    it.remove();
                } else {
                    break;
                }
            }

            if (timestamps.size() >= MAX_REGISTRATIONS_PER_IP) {
                return true;
            }

            timestamps.add(now);
            return false;
        }
    }

    /**
     * List users in the system, optionally filtered by username.
     * Endpoint: POST /admin/users
     * Body: { "filter": "optional-filter-string" }
     */
    public void listUsers(Context ctx) {
        try {
            String filter = "";
            String body = ctx.body();
            if (body != null && !body.isEmpty()) {
                JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();
                if (jBody.has("filter")) {
                    filter = jBody.get("filter").getAsString().trim();
                }
            }

            JsonArray users = mDb.findUsers(filter);
            if (users == null) {
                users = new JsonArray();
            }
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(users));
        } catch (DBException e) {
            LOGGER.warn("Failed to list users: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve users"));
        }
    }

    /**
     * Handle user actions (block, delete).
     * Endpoint: POST /admin/handleUser
     * Body: { "action": "block|delete", "username": "the-username" }
     */
    public void handleUser(Context ctx) {
        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();

        if (!jBody.has("action") || !jBody.has("username")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing required parameters: action and username"));
            return;
        }

        String action = jBody.get("action").getAsString();
        String username = jBody.get("username").getAsString();

        if (!"block".equals(action) && !"delete".equals(action) && !"confirm".equals(action)) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid action: " + action + ". Must be 'block', 'delete' or 'confirm'"));
            return;
        }

        try {
            if (!mDb.ifUserExists(username)) {
                ctx.status(404).result(JAux.statusResponse(404, "User \"" + username + "\" not found"));
                return;
            }

            if ("delete".equals(action)) {
                mDb.deleteUser(username);
                runUserScript("delete_user.sh", username);
                LOGGER.info("User \"{}\" deleted by admin", username);
                ctx.status(200).result(JAux.statusResponse(200, "User \"" + username + "\" has been deleted"));
            } else if ("confirm".equals(action)) {
                mDb.confirmUserByUsername(username);
                LOGGER.info("User \"{}\" confirmed by admin", username);
                ctx.status(200).result(JAux.statusResponse(200, "User \"" + username + "\" has been confirmed"));
            } else {
                // TODO: implement block logic
                LOGGER.info("User \"{}\" blocked by admin", username);
                ctx.status(200).result(JAux.statusResponse(200, "User \"" + username + "\" has been blocked"));
            }
        } catch (DBException e) {
            LOGGER.warn("Failed to {} user \"{}\": {}", action, username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to " + action + " user: " + e.getMessage()));
        }
    }

    /**
     * Create a new user account.
     * Endpoint: POST /register
     */
    public void createUser(Context ctx) {
        if (!mAllowRegistration) {
            ctx.status(403).result(JAux.statusResponse(403, "Account registration is currently disabled"));
            return;
        }

        if (isRateLimited(ctx.ip())) {
            LOGGER.info("Registration rate limit exceeded for IP: {}", ctx.ip());
            ctx.status(429).result(JAux.statusResponse(429, "Too many registration attempts. Please try again later."));
            return;
        }

        if (mAltchaService != null) {
            String body = ctx.body();
            String altchaPayload = null;
            try {
                altchaPayload = JsonParser.parseString(body).getAsJsonObject().get("altcha").getAsString();
            } catch (Exception ignored) {}

            if (altchaPayload == null || altchaPayload.isEmpty()) {
                ctx.status(400).result(JAux.statusResponse(400, "CAPTCHA verification required"));
                return;
            }
            if (!mAltchaService.verify(altchaPayload)) {
                LOGGER.warn("ALTCHA verification failed for IP: {}", ctx.ip());
                ctx.status(400).result(JAux.statusResponse(400, "CAPTCHA verification failed"));
                return;
            }
        }

        String rqstJson = ctx.body();

        String contentType = ctx.contentType();
        if (!"application/json".equalsIgnoreCase(contentType)) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid json request " + ctx.body()));
            return;
        }

        Map<String, String> tParams = paramsToMap(ctx);

        if (!tParams.containsKey(Profile.USERNAME)) {
            ctx.status(400).result(JAux.statusResponse(400, "Required parameter \"" + Profile.USERNAME + "\" is missing\n"));
            return;
        }

        try {
            String tUsername = tParams.get(Profile.USERNAME);
            if (mDb.ifUserExists(tUsername.toLowerCase())) {
                ctx.status(400).result(JAux.statusResponse(400, "Username: \"" + tUsername + "\" is already taken\n"));
                return;
            }

            // Generate confirmation UID
            String confUid = UUID.randomUUID().toString();
            JsonObject jUser = JsonParser.parseString(rqstJson).getAsJsonObject();
            jUser.addProperty(Profile.CONF_UID, confUid);

            // Create user entry in the DB
            try {
                mDb.createUser(jUser);
            } catch (Exception e) {
                ctx.status(500).result(JAux.statusResponse(500, "Failed to create user account, reason: " + e.getMessage() + "\n"));
                return;
            }

            // Create OS user
            runUserScript("create_user.sh", tUsername.toLowerCase());

            // Send confirmation email using the internal mailer credentials
            String confMail = tParams.get(Profile.CONFIRMATION_MAIL);
            if (confMail != null && !confMail.isEmpty()) {
                try {
                    sendConfirmationEmail(confMail, tUsername, confUid);
                } catch (Exception e) {
                    LOGGER.warn("Failed to send confirmation email to {}: {}", confMail, e.getMessage());
                }
            }

            sendAdminNotification(tUsername, confMail);
            LOGGER.info("User \"{}\" created successfully, confirmation email sent to {}", tUsername, confMail);
            ctx.status(200).result(JAux.statusResponse(200, "Account created. A confirmation email has been sent to " + confMail + "\n"));
        } catch (Exception e) {
            LOGGER.warn("Failed to create user: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to create user: " + e.getMessage()));
        }
    }

    /**
     * Create a new user account as admin (confirmed immediately, no confirmation email).
     * Endpoint: POST /admin/createUser
     */
    public void adminCreateUser(Context ctx) {
        String rqstJson = ctx.body();

        String contentType = ctx.contentType();
        if (!"application/json".equalsIgnoreCase(contentType)) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid json request " + ctx.body()));
            return;
        }

        Map<String, String> tParams = paramsToMap(ctx);

        if (!tParams.containsKey(Profile.USERNAME)) {
            ctx.status(400).result(JAux.statusResponse(400, "Required parameter \"" + Profile.USERNAME + "\" is missing\n"));
            return;
        }

        try {
            String tUsername = tParams.get(Profile.USERNAME);
            if (mDb.ifUserExists(tUsername.toLowerCase())) {
                ctx.status(400).result(JAux.statusResponse(400, "Username: \"" + tUsername + "\" is already taken\n"));
                return;
            }

            JsonObject jUser = JsonParser.parseString(rqstJson).getAsJsonObject();
            jUser.addProperty(Profile.CONFIRMED, true);

            try {
                mDb.createUser(jUser);
            } catch (Exception e) {
                ctx.status(500).result(JAux.statusResponse(500, "Failed to create user account, reason: " + e.getMessage() + "\n"));
                return;
            }

            // Create OS user
            runUserScript("create_user.sh", tUsername.toLowerCase());

            sendAdminNotification(tUsername, tParams.get(Profile.CONFIRMATION_MAIL));
            LOGGER.info("User \"{}\" created by admin (confirmed)", tUsername);
            ctx.status(200).result(JAux.statusResponse(200, "User \"" + tUsername + "\" created successfully\n"));
        } catch (Exception e) {
            LOGGER.warn("Failed to create user: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to create user: " + e.getMessage()));
        }
    }

    /**
     * Send an admin notification email when a new user is created, if configured and enabled.
     */
    private void sendAdminNotification(String username, String confirmationAddress) {
        if (!mAdminNotificationsEnabled || mAdminNotificationAddress == null || mAdminNotificationAddress.isBlank()) {
            return;
        }
        try {
            boolean useAuth = mInternalMailPassword != null && !mInternalMailPassword.isBlank();
            Properties props = new Properties();
            props.put("mail.smtp.host", mSmtpHost);
            props.put("mail.smtp.port", String.valueOf(mSmtpPort));
            props.put("mail.smtp.auth", String.valueOf(useAuth));
            if (mSmtpStartTls) {
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.ssl.trust", "*");
                props.put("mail.smtp.ssl.checkserveridentity", "false");
            }

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);
            String fromAddress = mInternalMailUser + "@" + mMailDomain;
            message.setFrom(new InternetAddress(fromAddress));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(mAdminNotificationAddress));
            message.setSubject("New ICEMail user created: " + username);

            String confInfo = (confirmationAddress != null && !confirmationAddress.isBlank())
                    ? "Confirmation address: " + confirmationAddress
                    : "No confirmation address provided (admin-created account).";
            String htmlBody = "<html><body>" +
                    "<h2>New ICEMail User Created</h2>" +
                    "<p>User <strong>" + username + "</strong> has been created.</p>" +
                    "<p>" + confInfo + "</p>" +
                    "</body></html>";
            message.setContent(htmlBody, "text/html; charset=utf-8");

            Transport transport = session.getTransport("smtp");
            try {
                if (useAuth) {
                    transport.connect(mSmtpHost, mSmtpPort, mInternalMailUser, mInternalMailPassword);
                } else {
                    transport.connect();
                }
                transport.sendMessage(message, message.getAllRecipients());
                LOGGER.info("Admin notification sent to {} for new user {}", mAdminNotificationAddress, username);
            } finally {
                transport.close();
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to send admin notification for user {}: {}", username, e.getMessage());
        }
    }

    /**
     * Send a confirmation email with a link to confirm the account.
     * Authenticates to the SMTP server using the internal mailer credentials.
     */
    private void sendConfirmationEmail(String toAddress, String username, String confUid) throws Exception {
        boolean useAuth = mInternalMailPassword != null && !mInternalMailPassword.isBlank();
        Properties props = new Properties();
        props.put("mail.smtp.host", mSmtpHost);
        props.put("mail.smtp.port", String.valueOf(mSmtpPort));
        props.put("mail.smtp.auth", String.valueOf(useAuth));
        if (mSmtpStartTls) {
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.ssl.trust", "*");
            props.put("mail.smtp.ssl.checkserveridentity", "false");
        }

        Session session = Session.getInstance(props);
        MimeMessage message = new MimeMessage(session);
        String fromAddress = mInternalMailUser + "@" + mMailDomain;
        message.setFrom(new InternetAddress(fromAddress));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(toAddress));
        message.setSubject("Confirm your ICEMail account");

        String confirmUrl = mBaseUrl + "/confirm.html?uid=" + confUid;
        String htmlBody = "<html><body>" +
                "<h2>Welcome to ICEMail</h2>" +
                "<p>Hi " + username + ",</p>" +
                "<p>Please confirm your account by clicking the link below:</p>" +
                "<p><a href=\"" + confirmUrl + "\">Confirm Account</a></p>" +
                "<p>If you did not create this account, you can ignore this email.</p>" +
                "</body></html>";

        message.setContent(htmlBody, "text/html; charset=utf-8");

        LOGGER.info("Sending confirmation email to {} from {}, SMTP {}:{}, user={}",
                toAddress, fromAddress, mSmtpHost, mSmtpPort, mInternalMailUser);

        Transport transport = session.getTransport("smtp");
        try {
            if (useAuth) {
                transport.connect(mSmtpHost, mSmtpPort, mInternalMailUser, mInternalMailPassword);
            } else {
                transport.connect();
            }
            transport.sendMessage(message, message.getAllRecipients());
            LOGGER.info("Confirmation email sent successfully to {}", toAddress);
        } catch (MessagingException e) {
            LOGGER.warn("Failed to send confirmation email to {}: {}", toAddress, e.getMessage());
            throw e;
        } finally {
            transport.close();
        }
    }

    /**
     * Run a shell script with the given username argument.
     * The script is expected to be in the server's working directory.
     */
    private void runUserScript(String scriptName, String username) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sudo", "./" + scriptName, username);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                LOGGER.info("{} succeeded for user \"{}\": {}", scriptName, username, output.toString().trim());
            } else {
                LOGGER.warn("{} failed for user \"{}\" (exit code {}): {}", scriptName, username, exitCode, output.toString().trim());
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to execute {} for user \"{}\": {}", scriptName, username, e.getMessage());
        }
    }

    /**
     * Parse request parameters from JSON body.
     */
    private Map<String, String> paramsToMap(Context ctx) {
        HashMap<String, String> tMap = new HashMap<>();

        if (ctx.method().toString().equals("POST")) {
            String jString = ctx.body();
            JsonObject jParams = JsonParser.parseString(jString).getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : jParams.entrySet()) {
                tMap.put(entry.getKey(), entry.getValue().getAsString());
            }
        }
        return tMap;
    }
}
