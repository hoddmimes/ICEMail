package com.hoddmimes.ice.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal Postfix policy service server.
 * Listens for Postfix smtpd_end_of_data_restrictions policy requests and
 * increments the sent-mail counter when the sender belongs to the local domain.
 * Always responds "dunno" (pass through) — never rejects.
 */
public class PostfixPolicyServer extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(PostfixPolicyServer.class);

    private final int mPort;
    private final String mMailDomain;
    private final ExecutorService mThreadPool = Executors.newCachedThreadPool();

    public PostfixPolicyServer(int port, String mailDomain) {
        mPort = port;
        mMailDomain = mailDomain;
        setDaemon(true);
        setName("postfix-policy-server");
    }

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(mPort)) {
            LOGGER.info("Postfix policy server listening on port {}", mPort);
            while (true) {
                Socket socket = serverSocket.accept();
                mThreadPool.submit(() -> handleConnection(socket));
            }
        } catch (Exception e) {
            LOGGER.error("Postfix policy server fatal error: {}", e.getMessage(), e);
        }
    }

    private void handleConnection(Socket socket) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

            // A single persistent connection may carry multiple policy requests
            while (true) {
                String sender = null;
                String line;

                // Read key=value pairs until blank line
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    if (line.startsWith("sender=")) {
                        sender = line.substring(7).trim();
                    }
                }

                if (line == null) {
                    break; // connection closed
                }

                // Count outbound mail from local users
                if (sender != null && !sender.isEmpty()
                        && sender.toLowerCase().endsWith("@" + mMailDomain.toLowerCase())) {
                    ServerStats.getInstance().recordMailSent();
                    LOGGER.info("Policy: recorded sent mail from {}", sender);
                }

                // Always pass through
                writer.write("action=dunno\n\n");
                writer.flush();
            }
        } catch (Exception e) {
            LOGGER.debug("Postfix policy connection closed: {}", e.getMessage());
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }
}
