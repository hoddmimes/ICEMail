package com.hoddmimes.ice.postfix_filter;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hoddmimes.ice.server.DBSqlite3;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class PostfixAfterQueueFilter extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(PostfixAfterQueueFilter.class);

    private static int sInboundPort  = 10026;
    private static int sOutboundPort = 10027;

    private static String sDbFile;
    private static String sBaseUrl;
    private static String sMailDomain;

    /**
     * Standalone constructor — reads its own config file.
     * Used when PostfixAfterQueueFilter runs as an independent process.
     */
    PostfixAfterQueueFilter(String configFile) {
        loadConfig(configFile);
        this.setDaemon(false);
        this.start();
    }

    /**
     * Embedded constructor — config already loaded by Server.
     * Ports come from the "postfix_after_queue" section of the server config.
     */
    public PostfixAfterQueueFilter(JsonObject jConfig, int port, int requeuePort) {
        sInboundPort  = port;
        sOutboundPort = requeuePort;
        extractConfig(jConfig);
        this.setDaemon(true);
        this.start();
    }

    private void extractConfig(JsonObject jConfig) {
        sBaseUrl = jConfig.has("base_url")
                ? jConfig.get("base_url").getAsString()
                : "https://localhost:8282";

        if (jConfig.has("mail_domain")) {
            sMailDomain = jConfig.get("mail_domain").getAsString();
        }

        JsonObject jDatabase = jConfig.get("database").getAsJsonObject();
        JsonObject jDbConfig  = jDatabase.get("configuration").getAsJsonObject();
        sDbFile = jDbConfig.get("db_file").getAsString();
    }

    private void loadConfig(String configFile) {
        try (FileReader reader = new FileReader(configFile)) {
            extractConfig(JsonParser.parseReader(reader).getAsJsonObject());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load config from " + configFile, e);
        }
    }

    @Override
    public void run() {
        try {
            ServerSocket serverSocket = new ServerSocket(sInboundPort);
            LOGGER.info("Postfix after-queue filter listening on port {}", sInboundPort);

            while (true) {
                Socket socket = serverSocket.accept();
                LOGGER.info("After-queue filter: inbound connection from {}", socket.getInetAddress());
                new ClientHandler(socket).start();
            }
        } catch (IOException e) {
            LOGGER.error("After-queue filter fatal error: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String configFile = "./server.json";
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-config") && i + 1 < args.length) {
                configFile = args[++i];
            }
        }
        new PostfixAfterQueueFilter(configFile);
    }


    // ===== Client handler =====

    static class ClientHandler extends Thread {

        private final Socket mSocket;

        ClientHandler(Socket socket) {
            mSocket = socket;
        }

        @Override
        public void run() {
            try {
                BufferedReader in  = new BufferedReader(new InputStreamReader(mSocket.getInputStream(),  StandardCharsets.ISO_8859_1));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(mSocket.getOutputStream(), StandardCharsets.ISO_8859_1));

                String from = null;
                List<String> recipients = new ArrayList<>();
                StringBuilder msgData = new StringBuilder();
                boolean inData = false;

                out.write("220 JavaEncryptor SMTP ready\r\n");
                out.flush();

                String line;
                while ((line = in.readLine()) != null) {
                    if (inData) {
                        if (line.equals(".")) break;
                        msgData.append(line).append("\r\n");
                        continue;
                    }

                    if (line.startsWith("MAIL FROM:")) {
                        from = line.substring(10).trim();
                        out.write("250 OK\r\n");
                    } else if (line.startsWith("RCPT TO:")) {
                        recipients.add(line.substring(8).trim());
                        out.write("250 OK\r\n");
                    } else if (line.equalsIgnoreCase("DATA")) {
                        out.write("354 End data with <CR><LF>.<CR><LF>\r\n");
                        inData = true;
                    } else if (line.startsWith("EHLO") || line.startsWith("HELO")) {
                        out.write("250 OK\r\n");
                    } else if (line.equalsIgnoreCase("QUIT")) {
                        out.write("221 Bye\r\n");
                        out.flush();
                        mSocket.close();
                    } else {
                        out.write("250 OK\r\n");
                    }
                    out.flush();
                }

                String raw = msgData.toString();
                int split = raw.indexOf("\r\n\r\n");
                if (split < 0) {
                    LOGGER.warn("After-queue filter: header/body separator not found, dropping message");
                    return;
                }

                String headers = raw.substring(0, split);
                String body    = raw.substring(split + 4);

                if (headers.contains("X-Filtered-By: JavaEncryptor")) {
                    requeue(from, recipients, raw);
                    return;
                }

                String iceUid = extractHeader(headers, "X-ICE-UID");
                if (iceUid != null) {
                    handleDecryptMessage(from, recipients, headers, body, iceUid);
                } else {
                    handlePgpEncryptForLocalUsers(from, recipients, headers, body);
                }

                out.write("250 OK\r\n");
                out.flush();

            } catch (Exception e) {
                LOGGER.error("After-queue filter: error handling connection: {}", e.getMessage(), e);
            } finally {
                try { mSocket.close(); } catch (IOException ignored) {}
            }
        }

        private void handlePgpEncryptForLocalUsers(String from, List<String> recipients,
                                                   String headers, String body) throws Exception {
            String filteredHeaders = headers + "\r\nX-Filtered-By: JavaEncryptor\r\n";

            if (sMailDomain == null || sMailDomain.isEmpty()) {
                requeue(from, recipients, filteredHeaders + "\r\n" + body);
                return;
            }

            List<String>   externalRecipients = new ArrayList<>();
            List<String[]> localRecipients    = new ArrayList<>();

            DBSqlite3 db = new DBSqlite3(sDbFile);
            try {
                db.connect();
                String domainSuffix = "@" + sMailDomain;

                for (String rcpt : recipients) {
                    String addr = rcpt.trim();
                    if (addr.startsWith("<") && addr.endsWith(">")) {
                        addr = addr.substring(1, addr.length() - 1);
                    }

                    if (addr.toLowerCase().endsWith(domainSuffix.toLowerCase())) {
                        String username  = addr.substring(0, addr.length() - domainSuffix.length());
                        String publicKey = db.findUserPublicKey(username);
                        if (publicKey != null && !publicKey.isEmpty()) {
                            localRecipients.add(new String[]{rcpt, publicKey});
                        } else {
                            externalRecipients.add(rcpt);
                        }
                    } else {
                        externalRecipients.add(rcpt);
                    }
                }
            } finally {
                db.close();
            }

            if (!externalRecipients.isEmpty()) {
                requeue(from, externalRecipients, filteredHeaders + "\r\n" + body);
            }

            for (String[] localRcpt : localRecipients) {
                String rcpt      = localRcpt[0];
                String publicKey = localRcpt[1];
                try {
                    String decodedBody = decodeBodyIfNeeded(headers, body);
                    String encryptedBody = PgpEncryptor.encrypt(decodedBody, publicKey);

                    StringBuilder newHeaders = new StringBuilder();
                    for (String headerLine : headers.split("\r\n")) {
                        if (!headerLine.toLowerCase().startsWith("content-type:") &&
                            !headerLine.toLowerCase().startsWith("content-transfer-encoding:")) {
                            newHeaders.append(headerLine).append("\r\n");
                        }
                    }
                    newHeaders.append("X-Filtered-By: JavaEncryptor\r\n");
                    newHeaders.append("Content-Type: text/plain; charset=UTF-8\r\n");
                    newHeaders.append("Content-Transfer-Encoding: 7bit\r\n");

                    requeue(from, List.of(rcpt), newHeaders + "\r\n" + encryptedBody);
                    LOGGER.info("After-queue filter: PGP-encrypted message for {}", rcpt);
                } catch (Exception e) {
                    LOGGER.warn("After-queue filter: PGP encrypt failed for {}, passing through: {}", rcpt, e.getMessage());
                    requeue(from, List.of(rcpt), filteredHeaders + "\r\n" + body);
                }
            }
        }

        private void handleDecryptMessage(String from, List<String> recipients,
                                          String headers, String body, String iceUid) throws Exception {
            String encryptedBody = extractEncryptedBody(body);
            if (encryptedBody == null) {
                LOGGER.warn("After-queue filter: X-ICE-UID present but no encrypted body markers, passing through");
                requeue(from, recipients, headers + "\r\nX-Filtered-By: JavaEncryptor\r\n\r\n" + body);
                return;
            }

            String sender = extractHeader(headers, "From");
            if (sender == null) sender = from;

            DBSqlite3 db = new DBSqlite3(sDbFile);
            try {
                db.connect();
                db.saveDecryptMessage(iceUid, encryptedBody, sender);
                LOGGER.info("After-queue filter: saved decrypt message with UID {}", iceUid);
            } finally {
                db.close();
            }

            String link     = sBaseUrl + "/decrypt.html?uid=" + iceUid;
            String htmlBody = "<html><body>" +
                    "<p>You have received an encrypted message.</p>" +
                    "<p>To read this message, open the following link and enter the password provided by the sender:</p>" +
                    "<p><a href=\"" + link + "\">" + link + "</a></p>" +
                    "</body></html>";

            StringBuilder newHeaders = new StringBuilder();
            for (String headerLine : headers.split("\r\n")) {
                if (!headerLine.toLowerCase().startsWith("x-ice-uid:") &&
                    !headerLine.toLowerCase().startsWith("content-type:") &&
                    !headerLine.toLowerCase().startsWith("content-transfer-encoding:")) {
                    newHeaders.append(headerLine).append("\r\n");
                }
            }
            newHeaders.append("X-Filtered-By: JavaEncryptor\r\n");
            newHeaders.append("Content-Type: text/html; charset=UTF-8\r\n");
            newHeaders.append("Content-Transfer-Encoding: 7bit\r\n");

            requeue(from, recipients, newHeaders + "\r\n" + htmlBody);
        }

        /**
         * Decode the message body before PGP encryption so the client sees clean text.
         *
         * - Simple messages with Content-Transfer-Encoding: quoted-printable are decoded directly.
         * - Multipart messages (e.g. Apple Mail multipart/alternative) are parsed via Jakarta Mail,
         *   which handles QP decoding and charset conversion for each inner part automatically.
         *   The best available text part (plain preferred over HTML) is returned.
         */
        private String decodeBodyIfNeeded(String headers, String body) {
            String contentType = extractHeader(headers, "Content-Type");
            boolean isMultipart = contentType != null && contentType.toLowerCase().contains("multipart");

            if (isMultipart) {
                try {
                    // Reconstruct the full raw message so Jakarta Mail can parse it correctly,
                    // including folded headers and per-part Content-Transfer-Encoding.
                    byte[] rawMsg = (headers + "\r\n\r\n" + body).getBytes(StandardCharsets.ISO_8859_1);
                    Session session = Session.getDefaultInstance(new java.util.Properties());
                    MimeMessage msg = new MimeMessage(session, new ByteArrayInputStream(rawMsg));
                    Object content = msg.getContent();
                    if (content instanceof Multipart) {
                        String decoded = extractTextFromMultipart((Multipart) content);
                        if (decoded != null && !decoded.isEmpty()) {
                            return decoded;
                        }
                    } else if (content instanceof String) {
                        return (String) content;
                    }
                } catch (Exception e) {
                    LOGGER.warn("After-queue filter: multipart decode failed, using raw body: {}", e.getMessage());
                }
                return body;
            }

            // Simple (non-multipart) message: decode QP if needed.
            String cte = extractHeader(headers, "Content-Transfer-Encoding");
            if (cte == null || !cte.trim().equalsIgnoreCase("quoted-printable")) {
                return body;
            }

            String charset = "UTF-8";
            if (contentType != null) {
                for (String param : contentType.split(";")) {
                    String p = param.trim();
                    if (p.toLowerCase().startsWith("charset=")) {
                        charset = p.substring(8).trim().replace("\"", "");
                        break;
                    }
                }
            }

            try {
                // Body was read as ISO-8859-1; recover the raw bytes for QP decoding.
                byte[] rawBytes = body.getBytes(StandardCharsets.ISO_8859_1);
                InputStream decoded = MimeUtility.decode(new ByteArrayInputStream(rawBytes), "quoted-printable");
                return new String(decoded.readAllBytes(), Charset.forName(charset));
            } catch (Exception e) {
                LOGGER.warn("After-queue filter: QP decode failed, using raw body: {}", e.getMessage());
                return body;
            }
        }

        /**
         * Walk a multipart tree and return the best text content found.
         * Prefers text/plain; falls back to text/html if no plain text is present.
         * Jakarta Mail's getContent() handles QP/base64 decoding and charset conversion.
         */
        private String extractTextFromMultipart(Multipart multipart) throws Exception {
            String plainText = null;
            String htmlText  = null;

            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);
                String ct = part.getContentType().toLowerCase();
                Object c  = part.getContent();

                if (ct.startsWith("text/plain") && c instanceof String) {
                    plainText = (String) c;
                } else if (ct.startsWith("text/html") && c instanceof String) {
                    htmlText = (String) c;
                } else if (c instanceof Multipart) {
                    String nested = extractTextFromMultipart((Multipart) c);
                    if (nested != null && !nested.isEmpty()) {
                        return nested;
                    }
                }
            }

            if (plainText != null) return plainText;
            return htmlText; // may be null — caller handles that
        }

        private String extractHeader(String headers, String headerName) {
            for (String line : headers.split("\r\n")) {
                if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                    return line.substring(headerName.length() + 1).trim();
                }
            }
            return null;
        }

        private String extractEncryptedBody(String body) {
            String begin = "-----BEGIN ICE ENCRYPTED MESSAGE-----";
            String end   = "-----END ICE ENCRYPTED MESSAGE-----";
            int s = body.indexOf(begin);
            int e = body.indexOf(end);
            if (s >= 0 && e > s) {
                return body.substring(s + begin.length(), e).trim();
            }
            return null;
        }

        private static void requeue(String from, List<String> recipients, String message) throws Exception {
            Socket s = new Socket("127.0.0.1", sOutboundPort);
            try {
                BufferedReader in  = new BufferedReader(new InputStreamReader(s.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));

                in.readLine(); // banner
                out.write("EHLO javaencryptor\r\n"); out.flush();
                String ehloLine;
                do { ehloLine = in.readLine(); } while (ehloLine != null && ehloLine.startsWith("250-"));
                out.write("MAIL FROM:" + from + "\r\n"); out.flush(); in.readLine();

                for (String r : recipients) {
                    out.write("RCPT TO:" + r + "\r\n"); out.flush(); in.readLine();
                }

                out.write("DATA\r\n"); out.flush(); in.readLine();

                for (String line : message.split("\r\n")) {
                    if (line.startsWith(".")) line = "." + line;
                    out.write(line + "\r\n");
                }
                out.write(".\r\n"); out.flush(); in.readLine();
                out.write("QUIT\r\n"); out.flush();
            } finally {
                s.close();
            }
        }
    }
}
