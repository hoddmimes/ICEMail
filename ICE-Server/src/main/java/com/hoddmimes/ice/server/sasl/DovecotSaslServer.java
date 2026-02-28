package com.hoddmimes.ice.server.sasl;

import com.hoddmimes.ice.server.DBSqlite3;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class DovecotSaslServer {
    private static final Logger LOGGER = LogManager.getLogger(DovecotSaslServer.class);

    private final int mPort;
    private final String mBindAddress;
    private final DBSqlite3 mDb;
    private ServerSocket mServerSocket;
    private Thread mListenerThread;
    private volatile boolean mRunning;
    private ExecutorService mExecutor;
    private final ConcurrentHashMap<String, String> mServiceUsers = new ConcurrentHashMap<>();

    public DovecotSaslServer(int pPort, String pBindAddress, DBSqlite3 pDb) {
        mPort = pPort;
        mBindAddress = pBindAddress;
        mDb = pDb;
    }

    public void addServiceUser(String username, String password) {
        mServiceUsers.put(username.toLowerCase(), password);
    }

    public void start() throws IOException {
        mExecutor = Executors.newFixedThreadPool(10);
        InetAddress bindAddr = InetAddress.getByName(mBindAddress);
        mServerSocket = new ServerSocket(mPort, 50, bindAddr);
        mRunning = true;

        mListenerThread = new Thread(this::acceptLoop, "DovecotSaslListener");
        mListenerThread.setDaemon(true);
        mListenerThread.start();

        LOGGER.info("Dovecot SASL server started on {}:{}", mBindAddress, mPort);
    }

    private void acceptLoop() {
        while (mRunning) {
            try {
                Socket socket = mServerSocket.accept();
                socket.setSoTimeout(60_000);
                mExecutor.submit(new DovecotSaslConnection(socket, mDb, mServiceUsers));
            } catch (IOException e) {
                if (mRunning) {
                    LOGGER.info("SASL accept error: {}", e.getMessage());
                }
            }
        }
    }

    public void stop() {
        mRunning = false;
        try {
            if (mServerSocket != null) {
                mServerSocket.close();
            }
        } catch (IOException ignored) {
        }
        if (mExecutor != null) {
            mExecutor.shutdown();
            try {
                mExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }
        LOGGER.info("Dovecot SASL server stopped");
    }
}
