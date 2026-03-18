package com.hoddmimes.ice.server.admin;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.hoddmimes.ice.server.DBBase;
import com.hoddmimes.ice.server.JAux;
import com.hoddmimes.ice.server.Profile;

import io.javalin.http.Context;
import jakarta.mail.Address;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.internet.InternetAddress;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Properties;

/**
 * Admin debug tool: access any user's mailbox via a temporary IMAP session
 * using the user's stored hashed password.
 */
public class AdminMailHandler {

    private static final Logger LOGGER = LogManager.getLogger(AdminMailHandler.class);

    private final DBBase mDb;
    private final String mImapHost;
    private final int mImapPort;
    private final boolean mImapSsl;

    public AdminMailHandler(DBBase db, String imapHost, int imapPort, boolean imapSsl) {
        this.mDb = db;
        this.mImapHost = imapHost;
        this.mImapPort = imapPort;
        this.mImapSsl = imapSsl;
    }

    /**
     * List messages in a user's folder.
     * Endpoint: GET /admin/mail/messages?user=<username>&folder=<folderName>
     */
    public void listMessages(Context ctx) {
        String username = ctx.queryParam("user");
        String folderName = ctx.queryParam("folder");

        if (username == null || username.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing user parameter"));
            return;
        }
        if (folderName == null || folderName.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing folder parameter"));
            return;
        }

        Store store = null;
        Folder folder = null;
        try {
            store = openImapSession(username);
            if (store == null) {
                ctx.status(502).result(JAux.statusResponse(502, "Cannot open IMAP session for user: " + username));
                return;
            }

            folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            folder.open(Folder.READ_ONLY);
            int total = folder.getMessageCount();
            JsonArray messages = new JsonArray();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");

            // Newest first
            for (int i = total; i >= 1; i--) {
                Message msg = folder.getMessage(i);
                JsonObject jMsg = new JsonObject();
                jMsg.addProperty("messageNumber", msg.getMessageNumber());
                jMsg.addProperty("subject", msg.getSubject() != null ? msg.getSubject() : "");

                Address[] from = msg.getFrom();
                jMsg.addProperty("from", from != null && from.length > 0 ? formatAddress(from[0]) : "");

                Address[] to = msg.getRecipients(Message.RecipientType.TO);
                jMsg.addProperty("to", to != null && to.length > 0 ? formatAddress(to[0]) : "");

                jMsg.addProperty("date", msg.getSentDate() != null ? sdf.format(msg.getSentDate()) : "");
                messages.add(jMsg);
            }

            folder.close(false);
            store.close();

            JsonObject response = new JsonObject();
            response.add("messages", messages);
            response.addProperty("total", total);
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(response));

        } catch (Exception e) {
            LOGGER.warn("Admin listMessages failed for user {}: {}", username, e.getMessage());
            closeQuietly(folder, store);
            ctx.status(500).result(JAux.statusResponse(500, "Failed to list messages: " + e.getMessage()));
        }
    }

    /**
     * Get raw RFC 822 content of a message.
     * Endpoint: GET /admin/mail/message/raw?user=<username>&folder=<folderName>&msg=<n>
     */
    public void getRawMessage(Context ctx) {
        String username = ctx.queryParam("user");
        String folderName = ctx.queryParam("folder");
        String msgNumStr = ctx.queryParam("msg");

        if (username == null || username.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing user parameter"));
            return;
        }
        if (folderName == null || folderName.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing folder parameter"));
            return;
        }
        if (msgNumStr == null || msgNumStr.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing msg parameter"));
            return;
        }

        int msgNum;
        try {
            msgNum = Integer.parseInt(msgNumStr);
        } catch (NumberFormatException e) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid message number"));
            return;
        }

        Store store = null;
        Folder folder = null;
        try {
            store = openImapSession(username);
            if (store == null) {
                ctx.status(502).result(JAux.statusResponse(502, "Cannot open IMAP session for user: " + username));
                return;
            }

            folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            folder.open(Folder.READ_ONLY);
            Message msg = folder.getMessage(msgNum);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            msg.writeTo(baos);
            String rawContent = baos.toString("UTF-8");

            folder.close(false);
            store.close();

            JsonObject response = new JsonObject();
            response.addProperty("raw", rawContent);
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(response));

        } catch (Exception e) {
            LOGGER.warn("Admin getRawMessage failed for user {}: {}", username, e.getMessage());
            closeQuietly(folder, store);
            ctx.status(500).result(JAux.statusResponse(500, "Failed to get message: " + e.getMessage()));
        }
    }

    private Store openImapSession(String username) {
        try {
            JsonObject jUser = mDb.findUser(username.toLowerCase());
            if (jUser == null) {
                LOGGER.warn("AdminMailHandler: user not found: {}", username);
                return null;
            }
            String password = jUser.get(Profile.PASSWORD).getAsString();
            return createImapSession(username, password);
        } catch (Exception e) {
            LOGGER.warn("AdminMailHandler: cannot get credentials for {}: {}", username, e.getMessage());
            return null;
        }
    }

    private Store createImapSession(String username, String password) {
        Properties props = new Properties();
        String protocol;

        if (mImapSsl) {
            protocol = "imaps";
            props.put("mail.store.protocol", "imaps");
            props.put("mail.imaps.host", mImapHost);
            props.put("mail.imaps.port", String.valueOf(mImapPort));
            props.put("mail.imaps.ssl.trust", "*");
            props.put("mail.imaps.ssl.checkserveridentity", "false");
            props.put("mail.imaps.ssl.protocols", "TLSv1.3 TLSv1.2");
            SSLSocketFactory sslSocketFactory = createTrustAllSocketFactory();
            if (sslSocketFactory != null) {
                props.put("mail.imaps.ssl.socketFactory", sslSocketFactory);
            }
        } else {
            protocol = "imap";
            props.put("mail.store.protocol", "imap");
            props.put("mail.imap.host", mImapHost);
            props.put("mail.imap.port", String.valueOf(mImapPort));
        }

        try {
            Session session = Session.getInstance(props);
            Store store = session.getStore(protocol);
            store.connect(mImapHost, mImapPort, username, password);
            return store;
        } catch (MessagingException e) {
            LOGGER.warn("AdminMailHandler: failed to create IMAP session for {}: {}", username, e.getMessage());
            return null;
        }
    }

    private SSLSocketFactory createTrustAllSocketFactory() {
        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }};
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            return sc.getSocketFactory();
        } catch (Exception e) {
            LOGGER.warn("AdminMailHandler: failed to create trust-all SSL factory: {}", e.getMessage());
            return null;
        }
    }

    private String formatAddress(Address addr) {
        if (addr instanceof InternetAddress ia) {
            String personal = ia.getPersonal();
            String email = ia.getAddress();
            if (personal != null && !personal.isEmpty()) {
                return personal + " <" + email + ">";
            }
            return email != null ? email : addr.toString();
        }
        return addr.toString();
    }

    private void closeQuietly(Folder folder, Store store) {
        if (folder != null && folder.isOpen()) {
            try { folder.close(false); } catch (Exception ignored) {}
        }
        if (store != null) {
            try { store.close(); } catch (Exception ignored) {}
        }
    }
}
