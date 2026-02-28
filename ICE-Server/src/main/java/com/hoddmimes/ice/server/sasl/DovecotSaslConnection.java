package com.hoddmimes.ice.server.sasl;

import com.google.gson.JsonObject;
import com.hoddmimes.ice.server.DBException;
import com.hoddmimes.ice.server.DBSqlite3;
import com.hoddmimes.ice.server.Profile;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class DovecotSaslConnection implements Runnable {
    private static final Logger LOGGER = LogManager.getLogger(DovecotSaslConnection.class);
    private static final AtomicInteger sCuidCounter = new AtomicInteger(1);

    private final Socket mSocket;
    private final DBSqlite3 mDb;
    private final int mCuid;
    private final ConcurrentHashMap<String, String> mServiceUsers;

    public DovecotSaslConnection(Socket pSocket, DBSqlite3 pDb, ConcurrentHashMap<String, String> pServiceUsers) {
        mSocket = pSocket;
        mDb = pDb;
        mCuid = sCuidCounter.getAndIncrement();
        mServiceUsers = pServiceUsers;
    }

    @Override
    public void run() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(mSocket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(mSocket.getOutputStream(), StandardCharsets.UTF_8))) {

            // Read client handshake: VERSION and CPID
            boolean versionReceived = false;
            boolean cpidReceived = false;

            while (!versionReceived || !cpidReceived) {
                String line = reader.readLine();
                if (line == null) {
                    return;
                }
                if (line.startsWith("VERSION\t")) {
                    versionReceived = true;
                } else if (line.startsWith("CPID\t")) {
                    cpidReceived = true;
                }
            }

            // Send server handshake
            long spid = ProcessHandle.current().pid();
            String cookie = generateCookie();

            writeLine(writer, "VERSION\t1\t2");
            writeLine(writer, "MECH\tPLAIN\tplaintext");
            writeLine(writer, "SPID\t" + spid);
            writeLine(writer, "CUID\t" + mCuid);
            writeLine(writer, "COOKIE\t" + cookie);
            writeLine(writer, "DONE");
            writer.flush();

            // Auth loop
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("AUTH\t")) {
                    handleAuth(line, reader, writer);
                }
            }

        } catch (Exception e) {
            LOGGER.info("SASL connection error: {}", e.getMessage());
        } finally {
            try {
                mSocket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void handleAuth(String authLine, BufferedReader reader, BufferedWriter writer) throws Exception {
        // AUTH\t<id>\tPLAIN\t[service=smtp\t...]\t[resp=<base64>]
        String[] parts = authLine.split("\t");
        if (parts.length < 3) {
            return;
        }

        String requestId = parts[1];
        String mechanism = parts[2];

        if (!"PLAIN".equals(mechanism)) {
            writeLine(writer, "FAIL\t" + requestId + "\treason=unsupported mechanism");
            writer.flush();
            return;
        }

        // Look for resp= parameter in the AUTH line
        String base64Resp = null;
        for (int i = 3; i < parts.length; i++) {
            if (parts[i].startsWith("resp=")) {
                base64Resp = parts[i].substring(5);
                break;
            }
        }

        // If no initial response, send CONT to request it
        if (base64Resp == null) {
            writeLine(writer, "CONT\t" + requestId + "\t");
            writer.flush();
            String contLine = reader.readLine();
            if (contLine == null) {
                return;
            }
            // Client responds with: CONT\t<id>\t<base64>
            String[] contParts = contLine.split("\t");
            if (contParts.length >= 3) {
                base64Resp = contParts[2];
            } else {
                writeLine(writer, "FAIL\t" + requestId + "\treason=invalid continuation");
                writer.flush();
                return;
            }
        }

        // Decode PLAIN: authzid\0username\0password
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Resp);
        } catch (IllegalArgumentException e) {
            writeLine(writer, "FAIL\t" + requestId + "\treason=invalid base64");
            writer.flush();
            return;
        }

        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        // Split on null bytes - format is: authzid\0username\0password
        int first = decodedStr.indexOf('\0');
        int second = decodedStr.indexOf('\0', first + 1);
        if (first < 0 || second < 0) {
            writeLine(writer, "FAIL\t" + requestId + "\treason=invalid PLAIN data");
            writer.flush();
            return;
        }

        String username = decodedStr.substring(first + 1, second);
        String password = decodedStr.substring(second + 1);

        // Strip @domain from username if present
        int atIndex = username.indexOf('@');
        if (atIndex >= 0) {
            username = username.substring(0, atIndex);
        }
        username = username.toLowerCase();

        // Check service users first (e.g. internal mailer)
        String servicePassword = mServiceUsers.get(username);
        if (servicePassword != null) {
            if (servicePassword.equals(password)) {
                LOGGER.info("SASL auth success (service user): {}", username);
                writeLine(writer, "OK\t" + requestId + "\tuser=" + username);
            } else {
                LOGGER.warn("SASL auth failed: wrong password for service user: {}", username);
                writeLine(writer, "FAIL\t" + requestId + "\treason=invalid credentials");
            }
            writer.flush();
            return;
        }

        // Authenticate against database
        try {
            JsonObject jUser = mDb.findUser(username);
            if (jUser == null) {
                LOGGER.warn("SASL auth failed: user not found: {}", username);
                writeLine(writer, "FAIL\t" + requestId + "\treason=invalid credentials");
                writer.flush();
                return;
            }

            if (!jUser.get(Profile.CONFIRMED).getAsBoolean()) {
                LOGGER.warn("SASL auth failed: account not confirmed: {}", username);
                writeLine(writer, "FAIL\t" + requestId + "\treason=account not confirmed");
                writer.flush();
                return;
            }

            if (jUser.get(Profile.BLOCKED).getAsBoolean()) {
                LOGGER.warn("SASL auth failed: account blocked: {}", username);
                writeLine(writer, "FAIL\t" + requestId + "\treason=account blocked");
                writer.flush();
                return;
            }

            String storedPassword = jUser.get(Profile.PASSWORD).getAsString();
            if (!storedPassword.equals(password)) {
                LOGGER.warn("SASL auth failed: wrong password for: {}", username);
                writeLine(writer, "FAIL\t" + requestId + "\treason=invalid credentials");
                writer.flush();
                return;
            }

            LOGGER.info("SASL auth success: {}", username);
            writeLine(writer, "OK\t" + requestId + "\tuser=" + username);
            writer.flush();

        } catch (DBException e) {
            LOGGER.info("SASL auth error: {}", e.getMessage());
            writeLine(writer, "FAIL\t" + requestId + "\treason=internal error");
            writer.flush();
        }
    }

    private void writeLine(BufferedWriter writer, String line) throws Exception {
        writer.write(line);
        writer.write('\n');
    }

    private String generateCookie() {
        byte[] bytes = new byte[16];
        new java.security.SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
