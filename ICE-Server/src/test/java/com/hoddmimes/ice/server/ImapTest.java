package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.mail.Folder;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Store;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class ImapTest
{
    private boolean mImapSsl = true;
    private String  mImapHost ="192.168.42.11";
    private int mImapPort = 993;



    private SSLSocketFactory createTrustAllSocketFactory() {
        try {
            // Set up a TrustManager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            return sc.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private Store createImapSession(String pImapHost, int pImapPort, boolean pUseSSL, String pUsername, String pPassword) {
        Properties props = new Properties();
        String protocol;

        if (pUseSSL) {
            protocol = "imaps";
            props.put("mail.imaps.host", pImapHost);
            props.put("mail.imaps.port", String.valueOf(pImapPort));
            props.put("mail.imaps.connectiontimeout", "10000");
            props.put("mail.imaps.timeout", "10000");
            props.put("mail.imaps.ssl.trust", "*");
            props.put("mail.imaps.ssl.checkserveridentity", "false");
            props.put("mail.imaps.ssl.protocols", "TLSv1.3 TLSv1.2");
            // Set custom SSL socket factory that trusts all certificates
            SSLSocketFactory sslSocketFactory = createTrustAllSocketFactory();
            if (sslSocketFactory != null) {
                props.put("mail.imaps.ssl.socketFactory", sslSocketFactory);
            }
        } else {
            protocol = "imap";
            props.put("mail.store.protocol", "imap");
            props.put("mail.imap.host", pImapHost);
            props.put("mail.imap.port", String.valueOf(pImapPort));
        }

        try {
            Session session = Session.getInstance(props);
            System.out.println("IMAP session created for user: " + pUsername + " (SSL: " + pUseSSL + ")");
            Store store = session.getStore(protocol);
            System.out.println("IMAP store created for user: " + pUsername + " (SSL: " + pUseSSL + ")");
            store.connect(pImapHost, pImapPort, pUsername, pPassword);
            System.out.println("IMAP session connected for user: " + pUsername + " (SSL: " + pUseSSL + ")");
            return store;
        } catch (MessagingException e) {
            System.out.println("Failed to create IMAP session for user " + pUsername + ": " + e.getMessage());
            return null;
        }
    }


    public static void main(String[] args) {
        ImapTest tst = new ImapTest();

        tst.test( args );
    }

    private void test(String[] args) {

        String tUsername = null;
        String tPassword = null;
        int i = 0;
        while( i < args.length ) {
            if (args[i].compareToIgnoreCase("-user") == 0) {
                tUsername = args[++i];
            }
            if (args[i].compareToIgnoreCase("-password") == 0) {
                tPassword = args[++i];
            }
        }

        if ((tUsername == null) || (tPassword == null)) {
            throw new RuntimeException("required pgm parameters -username and/or -password is missing");
        }

        Store tStore = createImapSession(mImapHost, mImapPort, mImapSsl, tUsername, tPassword);
        try {
            JsonArray mailboxes = new JsonArray();
            Folder defaultFolder = tStore.getDefaultFolder();
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
                        jFolder.addProperty("error", e.getMessage());
                    }
                }

                mailboxes.add(jFolder);
            }

            if (mailboxes.size() == 0) {
                System.out.println("No mailboxes found");
            } else {
                for (int j = 0; j < mailboxes.size(); j++) {
                    JsonObject mbox = mailboxes.get(j).getAsJsonObject();
                    System.out.println( mbox.toString());
                }
            }
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

}
