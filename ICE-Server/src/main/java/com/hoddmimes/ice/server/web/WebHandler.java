package com.hoddmimes.ice.server.web;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hoddmimes.ice.server.JAux;
import com.hoddmimes.ice.server.Profile;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.javalin.http.Context;
import io.javalin.http.UploadedFile;

import jakarta.activation.DataHandler;
import jakarta.mail.Address;
import jakarta.mail.BodyPart;
import jakarta.mail.Flags;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * Handles web-related API endpoints for mailbox and message operations.
 */
public class WebHandler {

    private static final Logger LOGGER = LogManager.getLogger(WebHandler.class);

    private final int mMessagesBatchSize;
    private final String mSmtpHost;
    private final int mSmtpPort;
    private final boolean mSmtpStartTls;
    private final String mMailDomain;

    public WebHandler(int messagesBatchSize, String smtpHost, int smtpPort, boolean smtpStartTls, String mailDomain) {
        this.mMessagesBatchSize = messagesBatchSize;
        this.mSmtpHost = smtpHost;
        this.mSmtpPort = smtpPort;
        this.mSmtpStartTls = smtpStartTls;
        this.mMailDomain = mailDomain;
    }

    /**
     * List all mailboxes/folders for the authenticated user.
     * Endpoint: GET /web/mailboxes
     */
    public void listMailboxes(Context ctx) {
        Store store = (Store) ctx.req().getSession().getAttribute("imap_session");
        if (store == null) {
            ctx.status(401).result(JAux.statusResponse(401, "No IMAP session available"));
            return;
        }

        try {
            JsonArray mailboxes = new JsonArray();
            Folder defaultFolder = store.getDefaultFolder();
            Folder[] folders = defaultFolder.list("*");

            for (Folder folder : folders) {
                JsonObject jFolder = new JsonObject();
                jFolder.addProperty("name", folder.getName());
                jFolder.addProperty("fullName", folder.getFullName());
                jFolder.addProperty("type", folder.getType());

                // Check if folder can hold messages
                if ((folder.getType() & Folder.HOLDS_MESSAGES) != 0) {
                    try {
                        folder.open(Folder.READ_ONLY);
                        jFolder.addProperty("messageCount", folder.getMessageCount());
                        jFolder.addProperty("unreadCount", folder.getUnreadMessageCount());
                        folder.close(false);
                    } catch (MessagingException e) {
                        // Folder may not have a valid mbox file yet (empty/new mailbox)
                        jFolder.addProperty("error", true);
                        LOGGER.info("mailbox: {} not valid, reason: {}", folder.getName(), e.getMessage());
                    }
                }
                if (!jFolder.has("error")) {
                    if (jFolder.has("messageCount") && (jFolder.get("messageCount").getAsInt() > 0)) {
                        mailboxes.add(jFolder);
                    }
                }
            }
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(mailboxes));
        } catch (MessagingException e) {
            LOGGER.warn("Failed to list mailboxes: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve mailboxes"));
        }
    }

    /**
     * List messages in a folder with pagination support.
     * Endpoint: GET /web/messages?folder=<name>&offset=<n>
     */
    public void listMessages(Context ctx) {
        Store store = (Store) ctx.req().getSession().getAttribute("imap_session");
        if (store == null) {
            ctx.status(401).result(JAux.statusResponse(401, "No IMAP session available"));
            return;
        }

        String folderName = ctx.queryParam("folder");
        if (folderName == null || folderName.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing folder parameter"));
            return;
        }

        // Parse offset parameter (default 0)
        int offset = 0;
        String offsetStr = ctx.queryParam("offset");
        if (offsetStr != null && !offsetStr.isEmpty()) {
            try {
                offset = Integer.parseInt(offsetStr);
            } catch (NumberFormatException e) {
                ctx.status(400).result(JAux.statusResponse(400, "Invalid offset parameter"));
                return;
            }
        }

        try {
            Folder folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            folder.open(Folder.READ_ONLY);
            JsonArray messages = new JsonArray();

            int totalMessages = folder.getMessageCount();
            int batchSize = mMessagesBatchSize;

            // Calculate start and end indices (messages are 1-indexed, we show newest first)
            // offset=0 means start from newest, offset=25 means skip 25 newest
            int startIdx = totalMessages - offset;
            int endIdx = Math.max(1, startIdx - batchSize + 1);

            // Fetch messages in reverse order (newest first)
            for (int i = startIdx; i >= endIdx && i >= 1; i--) {
                Message msg = folder.getMessage(i);
                JsonObject jMsg = new JsonObject();

                jMsg.addProperty("messageNumber", msg.getMessageNumber());
                jMsg.addProperty("subject", msg.getSubject());

                // Get sender
                Address[] fromAddrs = msg.getFrom();
                if (fromAddrs != null && fromAddrs.length > 0) {
                    jMsg.addProperty("from", formatAddress(fromAddrs[0]));
                } else {
                    jMsg.addProperty("from", "");
                }

                // Get recipients
                Address[] toAddrs = msg.getRecipients(Message.RecipientType.TO);
                if (toAddrs != null && toAddrs.length > 0) {
                    jMsg.addProperty("to", formatAddress(toAddrs[0]));
                } else {
                    jMsg.addProperty("to", "");
                }

                // Get date
                if (msg.getSentDate() != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
                    jMsg.addProperty("date", sdf.format(msg.getSentDate()));
                } else {
                    jMsg.addProperty("date", "");
                }

                // Check if unread
                boolean unread = !msg.isSet(Flags.Flag.SEEN);
                jMsg.addProperty("unread", unread);

                messages.add(jMsg);
            }

            folder.close(false);

            // Build response with metadata
            JsonObject response = new JsonObject();
            response.add("messages", messages);
            response.addProperty("total", totalMessages);
            response.addProperty("offset", offset);
            response.addProperty("batchSize", batchSize);
            response.addProperty("hasMore", endIdx > 1);

            ctx.status(200).contentType("application/json").result(JAux.statusResponse(response));
        } catch (MessagingException e) {
            LOGGER.warn("Failed to list messages: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve messages"));
        }
    }

    /**
     * Get a single message with full content.
     * Endpoint: GET /web/message?folder=<name>&msg=<num>
     */
    public void getMessage(Context ctx) {
        Store store = (Store) ctx.req().getSession().getAttribute("imap_session");
        if (store == null) {
            ctx.status(401).result(JAux.statusResponse(401, "No IMAP session available"));
            return;
        }

        String folderName = ctx.queryParam("folder");
        String msgNumStr = ctx.queryParam("msg");

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

        try {
            Folder folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            folder.open(Folder.READ_ONLY);
            Message msg = folder.getMessage(msgNum);

            JsonObject jMsg = new JsonObject();
            jMsg.addProperty("messageNumber", msg.getMessageNumber());
            jMsg.addProperty("subject", msg.getSubject() != null ? msg.getSubject() : "");

            // Get sender
            Address[] fromAddrs = msg.getFrom();
            if (fromAddrs != null && fromAddrs.length > 0) {
                jMsg.addProperty("from", formatAddress(fromAddrs[0]));
            } else {
                jMsg.addProperty("from", "");
            }

            // Get recipients
            Address[] toAddrs = msg.getRecipients(Message.RecipientType.TO);
            if (toAddrs != null && toAddrs.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < toAddrs.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(formatAddress(toAddrs[i]));
                }
                jMsg.addProperty("to", sb.toString());
            } else {
                jMsg.addProperty("to", "");
            }

            // Get date
            if (msg.getSentDate() != null) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                jMsg.addProperty("date", sdf.format(msg.getSentDate()));
            } else {
                jMsg.addProperty("date", "");
            }

            // Get body content
            String body = getTextContent(msg);
            jMsg.addProperty("body", body);

            // Collect attachment metadata
            JsonArray attachments = collectAttachments(msg);
            if (attachments.size() > 0) {
                jMsg.add("attachments", attachments);
            }

            folder.close(false);
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(jMsg));
        } catch (MessagingException e) {
            LOGGER.warn("Failed to get message: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve message"));
        } catch (IOException e) {
            LOGGER.warn("Failed to read message content: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to read message content"));
        }
    }

    /**
     * Format an address for display, decoding RFC 2047 encoded personal names.
     * InternetAddress.toString() returns the raw encoded form; getPersonal() gives decoded text.
     */
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

    /**
     * Extract text content from a message, handling multipart messages.
     */
    private String getTextContent(Message msg) throws MessagingException, IOException {
        Object content = msg.getContent();

        if (content instanceof String) {
            return (String) content;
        } else if (content instanceof jakarta.mail.Multipart) {
            jakarta.mail.Multipart multipart = (jakarta.mail.Multipart) content;
            return getTextFromMultipart(multipart);
        }

        return "";
    }

    private String getTextFromMultipart(Multipart multipart) throws MessagingException, IOException {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < multipart.getCount(); i++) {
            BodyPart bodyPart = multipart.getBodyPart(i);
            String contentType = bodyPart.getContentType().toLowerCase();

            if (contentType.startsWith("text/plain")) {
                result.append(bodyPart.getContent().toString());
            } else if (contentType.startsWith("text/html") && result.length() == 0) {
                // Use HTML only if no plain text found
                result.append(bodyPart.getContent().toString());
            } else if (bodyPart.getContent() instanceof Multipart) {
                result.append(getTextFromMultipart((Multipart) bodyPart.getContent()));
            }
        }

        return result.toString();
    }

    /**
     * Collect attachment metadata from a message.
     * Returns a JsonArray of attachment info objects with partIndex, filename, size, contentType.
     */
    private JsonArray collectAttachments(Message msg) throws MessagingException, IOException {
        JsonArray attachments = new JsonArray();
        Object content = msg.getContent();

        if (content instanceof Multipart) {
            List<BodyPart> parts = new ArrayList<>();
            flattenParts((Multipart) content, parts);

            int partIndex = 0;
            for (BodyPart part : parts) {
                String contentType = part.getContentType().toLowerCase();
                String disposition = part.getDisposition();

                boolean isAttachment = Part.ATTACHMENT.equalsIgnoreCase(disposition);
                boolean isInlineNonText = Part.INLINE.equalsIgnoreCase(disposition)
                        && !contentType.startsWith("text/");
                boolean isNonTextPart = !contentType.startsWith("text/plain")
                        && !contentType.startsWith("text/html")
                        && !(part.getContent() instanceof Multipart);

                if (isAttachment || isInlineNonText || isNonTextPart) {
                    JsonObject jAtt = new JsonObject();
                    jAtt.addProperty("partIndex", partIndex);

                    String filename = part.getFileName();
                    if (filename == null || filename.isEmpty()) {
                        filename = "attachment_" + partIndex;
                    }
                    jAtt.addProperty("filename", filename);

                    int size = part.getSize();
                    if (size >= 0) {
                        jAtt.addProperty("size", size);
                    }

                    // Strip parameters from content type (e.g. "image/jpeg; name=foo" -> "image/jpeg")
                    String baseType = contentType;
                    int semicolonIdx = baseType.indexOf(';');
                    if (semicolonIdx > 0) {
                        baseType = baseType.substring(0, semicolonIdx).trim();
                    }

                    // If MIME type is generic, try to infer from filename
                    if ("application/octet-stream".equals(baseType)) {
                        String guessed = java.net.URLConnection.guessContentTypeFromName(filename);
                        if (guessed != null) {
                            baseType = guessed;
                        }
                    }
                    jAtt.addProperty("contentType", baseType);

                    attachments.add(jAtt);
                }
                partIndex++;
            }
        }

        return attachments;
    }

    /**
     * Delete a message from a folder.
     * Endpoint: POST /web/message/delete
     * Body: JSON { "folder": "<name>", "msg": <messageNumber> }
     */
    public void deleteMessage(Context ctx) {
        Store store = (Store) ctx.req().getSession().getAttribute("imap_session");
        if (store == null) {
            ctx.status(401).result(JAux.statusResponse(401, "No IMAP session available"));
            return;
        }

        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody;
        try {
            jBody = JsonParser.parseString(body).getAsJsonObject();
        } catch (Exception e) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid JSON body"));
            return;
        }

        if (!jBody.has("folder") || !jBody.has("msg")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing folder or msg parameter"));
            return;
        }

        String folderName = jBody.get("folder").getAsString();
        int msgNum;
        try {
            msgNum = jBody.get("msg").getAsInt();
        } catch (Exception e) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid message number"));
            return;
        }

        Folder folder = null;
        try {
            folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            if (folder.isOpen()) {
                folder.close(false);
            }

            folder.open(Folder.READ_WRITE);
            Message msg = folder.getMessage(msgNum);
            msg.setFlag(Flags.Flag.DELETED, true);
            folder.expunge();
            folder.close(false);

            LOGGER.info("Message {} deleted from folder {}", msgNum, folderName);
            ctx.status(200).result(JAux.statusResponse(200, "Message deleted"));
        } catch (Exception e) {
            LOGGER.warn("Failed to delete message: {}: {}", e.getClass().getSimpleName(), e.getMessage());
            if (folder != null && folder.isOpen()) {
                try { folder.close(false); } catch (Exception ignored) {}
            }
            ctx.status(500).result(JAux.statusResponse(500, "Failed to delete message: " + e.getMessage()));
        }
    }

    /**
     * Flatten a multipart tree into a list of leaf BodyParts.
     */
    private void flattenParts(Multipart multipart, List<BodyPart> parts) throws MessagingException, IOException {
        for (int i = 0; i < multipart.getCount(); i++) {
            BodyPart bodyPart = multipart.getBodyPart(i);
            Object content = bodyPart.getContent();
            if (content instanceof Multipart) {
                flattenParts((Multipart) content, parts);
            } else {
                parts.add(bodyPart);
            }
        }
    }

    /**
     * Send a new mail message.
     * Endpoint: POST /web/compose/send (multipart/form-data)
     */
    public void sendMessage(Context ctx) {
        JsonObject jUser = (JsonObject) ctx.req().getSession().getAttribute("username");
        if (jUser == null) {
            ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
            return;
        }

        String username = jUser.get(Profile.USERNAME).getAsString();
        String pbkdf2Password = jUser.get(Profile.PASSWORD).getAsString();
        String fromAddress = username + "@" + mMailDomain;

        String to = ctx.formParam("to");
        String cc = ctx.formParam("cc");
        String bcc = ctx.formParam("bcc");
        String subject = ctx.formParam("subject");
        String body = ctx.formParam("body");
        String iceUid = ctx.formParam("iceUid");

        if (to == null || to.trim().isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Recipient (To) is required"));
            return;
        }

        List<UploadedFile> attachments = ctx.uploadedFiles("attachments");

        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", mSmtpHost);
            props.put("mail.smtp.port", String.valueOf(mSmtpPort));
            props.put("mail.smtp.auth", "true");
            if (mSmtpStartTls) {
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.ssl.trust", "*");
                props.put("mail.smtp.ssl.checkserveridentity", "false");
                try {
                    TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] c, String a) {}
                        public void checkServerTrusted(X509Certificate[] c, String a) {}
                    }};
                    SSLContext sc = SSLContext.getInstance("TLS");
                    sc.init(null, trustAll, new java.security.SecureRandom());
                    props.put("mail.smtp.ssl.socketFactory", sc.getSocketFactory());
                } catch (GeneralSecurityException e) {
                    LOGGER.warn("Failed to configure trust-all SSL for SMTP: {}", e.getMessage());
                }
            }

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(fromAddress));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to.trim()));

            if (iceUid != null && !iceUid.trim().isEmpty()) {
                message.setHeader("X-ICE-UID", iceUid.trim());
            }

            if (cc != null && !cc.trim().isEmpty()) {
                message.setRecipients(Message.RecipientType.CC, InternetAddress.parse(cc.trim()));
            }
            if (bcc != null && !bcc.trim().isEmpty()) {
                message.setRecipients(Message.RecipientType.BCC, InternetAddress.parse(bcc.trim()));
            }

            message.setSubject(subject != null ? subject : "");
            message.setSentDate(new Date());

            if (attachments == null || attachments.isEmpty()) {
                message.setText(body != null ? body : "", "UTF-8");
            } else {
                MimeMultipart multipart = new MimeMultipart();

                MimeBodyPart textPart = new MimeBodyPart();
                textPart.setText(body != null ? body : "", "UTF-8");
                multipart.addBodyPart(textPart);

                for (UploadedFile file : attachments) {
                    MimeBodyPart filePart = new MimeBodyPart();
                    byte[] fileBytes = file.content().readAllBytes();
                    ByteArrayDataSource dataSource = new ByteArrayDataSource(fileBytes, file.contentType());
                    dataSource.setName(file.filename());
                    filePart.setDataHandler(new DataHandler(dataSource));
                    filePart.setFileName(file.filename());
                    multipart.addBodyPart(filePart);
                }

                message.setContent(multipart);
            }

            Transport transport = session.getTransport("smtp");
            transport.connect(mSmtpHost, mSmtpPort, username, pbkdf2Password);
            transport.sendMessage(message, message.getAllRecipients());
            transport.close();

            LOGGER.info("Message sent by {} to {}", username, to);
            ctx.status(200).result(JAux.statusResponse(200, "Message sent"));

        } catch (MessagingException e) {
            LOGGER.warn("Failed to send message for {}: {}", username, e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to send message: " + e.getMessage()));
        } catch (IOException e) {
            LOGGER.warn("Failed to read attachment: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to read attachment"));
        }
    }

    /**
     * Download/view an individual attachment.
     * Endpoint: GET /web/attachment?folder=X&msg=N&part=P
     */
    public void getAttachment(Context ctx) {
        Store store = (Store) ctx.req().getSession().getAttribute("imap_session");
        if (store == null) {
            ctx.status(401).result(JAux.statusResponse(401, "No IMAP session available"));
            return;
        }

        String folderName = ctx.queryParam("folder");
        String msgNumStr = ctx.queryParam("msg");
        String partIdxStr = ctx.queryParam("part");

        if (folderName == null || folderName.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing folder parameter"));
            return;
        }
        if (msgNumStr == null || msgNumStr.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing msg parameter"));
            return;
        }
        if (partIdxStr == null || partIdxStr.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing part parameter"));
            return;
        }

        int msgNum;
        int partIdx;
        try {
            msgNum = Integer.parseInt(msgNumStr);
            partIdx = Integer.parseInt(partIdxStr);
        } catch (NumberFormatException e) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid msg or part parameter"));
            return;
        }

        try {
            Folder folder = store.getFolder(folderName);
            if (!folder.exists()) {
                ctx.status(404).result(JAux.statusResponse(404, "Folder not found: " + folderName));
                return;
            }

            folder.open(Folder.READ_ONLY);
            Message msg = folder.getMessage(msgNum);
            Object content = msg.getContent();

            if (!(content instanceof Multipart)) {
                folder.close(false);
                ctx.status(404).result(JAux.statusResponse(404, "Message has no attachments"));
                return;
            }

            List<BodyPart> parts = new ArrayList<>();
            flattenParts((Multipart) content, parts);

            if (partIdx < 0 || partIdx >= parts.size()) {
                folder.close(false);
                ctx.status(404).result(JAux.statusResponse(404, "Attachment part not found"));
                return;
            }

            BodyPart bodyPart = parts.get(partIdx);

            // Determine content type
            String contentType = bodyPart.getContentType();
            int semicolonIdx = contentType.indexOf(';');
            String baseType = semicolonIdx > 0 ? contentType.substring(0, semicolonIdx).trim() : contentType;

            // If MIME type is generic, try to infer from filename
            if ("application/octet-stream".equalsIgnoreCase(baseType)) {
                String fname = bodyPart.getFileName();
                if (fname != null) {
                    String guessed = java.net.URLConnection.guessContentTypeFromName(fname);
                    if (guessed != null) {
                        baseType = guessed;
                    }
                }
            }

            // Read attachment bytes via DataHandler to ensure proper decoding
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            bodyPart.getDataHandler().writeTo(baos);
            byte[] data = baos.toByteArray();
            folder.close(false);

            LOGGER.info("Serving attachment: contentType={} filename={} size={} bytes", baseType, bodyPart.getFileName(), data.length);

            ctx.status(200);
            ctx.contentType(baseType);
            ctx.header("Content-Disposition", "inline");
            ctx.result(data);
        } catch (MessagingException e) {
            LOGGER.warn("Failed to get attachment: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to retrieve attachment"));
        } catch (IOException e) {
            LOGGER.warn("Failed to read attachment content: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to read attachment content"));
        }
    }
}
