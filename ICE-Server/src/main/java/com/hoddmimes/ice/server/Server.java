package com.hoddmimes.ice.server;



import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hoddmimes.ice.server.admin.ImapRestApi;
import io.javalin.Javalin;
import io.javalin.community.ssl.SslPlugin;
import io.javalin.http.Context;
import io.javalin.http.HttpResponseException;
import io.javalin.http.staticfiles.Location;
import io.javalin.json.JavalinJackson;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.eclipse.jetty.server.session.SessionHandler;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Store;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.*;
import java.security.cert.X509Certificate;

import com.hoddmimes.ice.server.admin.AdminHandler;
import com.hoddmimes.ice.server.sasl.DovecotSaslServer;
import com.hoddmimes.ice.server.web.ContactHandler;
import com.hoddmimes.ice.server.web.WebHandler;
import com.hoddmimes.ice.postfix_filter.PostfixAfterQueueFilter;

import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


public class Server
{
    private static final Logger LOGGER = LogManager.getLogger(Server.class);

    JsonObject  jConfig = null;
    boolean     mVerbose = false;
    DBSqlite3   db;
    Javalin     mApp;
    static Server sInstance;

    // Base URL for constructing confirmation links
    String      mBaseUrl = "https://localhost:8282";

    // Whether public account registration is enabled
    boolean     mAllowRegistration = false;

    // Mail domain for constructing email addresses
    String      mMailDomain = "localhost";

    // IMAP server configuration
    String      mImapHost = "localhost";
    int         mImapPort = 993;
    boolean     mImapSsl = true;
    int         mMessagesBatchSize = 25;

    // SMTP submission configuration
    String      mSmtpHost = "localhost";
    int         mSmtpPort = 587;
    boolean     mSmtpStartTls = true;

    // Web handler for mailbox/message operations
    WebHandler  mWebHandler;
    ImapRestApi mImapWebApi;

    // Admin handler for user management
    AdminHandler mAdminHandler;

    // Internal mailer configuration
    String      mInternalMailUser = null;
    String      mInternalMailPassword = null;
    String      mInternalMailSmtpHost = "localhost";
    int         mInternalMailSmtpPort = 25;
    boolean     mInternalMailStartTls = false;

    // Dovecot SASL server
    DovecotSaslServer mSaslServer;


    private void logStartupInfo() {
        LOGGER.info("Working directory: {}", System.getProperty("user.dir"));

        LoggerContext logCtx = (LoggerContext) LogManager.getContext(false);
        org.apache.logging.log4j.core.config.Configuration logConfig = logCtx.getConfiguration();

        LOGGER.info("Log4j2 root level: {}", logConfig.getRootLogger().getLevel());
        for (Map.Entry<String, org.apache.logging.log4j.core.Appender> entry : logConfig.getAppenders().entrySet()) {
            LOGGER.info("Log4j2 appender: {} ({})", entry.getKey(), entry.getValue().getClass().getSimpleName());
        }
        for (Map.Entry<String, LoggerConfig> entry : logConfig.getLoggers().entrySet()) {
            if (!entry.getKey().isEmpty()) {
                LOGGER.info("Log4j2 logger: {} level={}", entry.getKey(), entry.getValue().getLevel());
            }
        }
    }

    private void loadConfig(String[] pArgs) {
        int i = 0;

        String tConfigFilename = "./server.json";

        while (i < pArgs.length) {
            if (pArgs[i].contentEquals("-config")) {
                tConfigFilename = pArgs[++i];
            }
            i++;
        }

        // load server API keys
        try {
            LOGGER.info("Loading server configuration from file: " + tConfigFilename);
            jConfig = JsonParser.parseReader(new FileReader(tConfigFilename)).getAsJsonObject();

            if (jConfig.has("use_ipv4")) {
                System.setProperty("java.net.preferIPv4Stack", String.valueOf(jConfig.get("use_ipv4").getAsBoolean()));
                LOGGER.info("Using Tcp/Ip v4 stack");
            }


            if (jConfig.has("verbose")) {
                mVerbose  = Boolean.parseBoolean(jConfig.get("verbose").getAsString());
            }

            if (jConfig.has("base_url")) {
                mBaseUrl = jConfig.get("base_url").getAsString();
            }

            if (jConfig.has("allow_registration")) {
                mAllowRegistration = jConfig.get("allow_registration").getAsBoolean();
            }

            if (jConfig.has("mail_domain")) {
                mMailDomain = jConfig.get("mail_domain").getAsString();
            }

            if (jConfig.has("imap_host")) {
                mImapHost = jConfig.get("imap_host").getAsString();
            }
            if (jConfig.has("imap_port")) {
                mImapPort = jConfig.get("imap_port").getAsInt();
            }
            if (jConfig.has("imap_ssl")) {
                mImapSsl = jConfig.get("imap_ssl").getAsBoolean();
            }
            if (jConfig.has("messages_batch_size")) {
                mMessagesBatchSize = jConfig.get("messages_batch_size").getAsInt();
            }

            if (jConfig.has("smtp_host")) {
                mSmtpHost = jConfig.get("smtp_host").getAsString();
            }
            if (jConfig.has("smtp_port")) {
                mSmtpPort = jConfig.get("smtp_port").getAsInt();
            }
            if (jConfig.has("smtp_starttls")) {
                mSmtpStartTls = jConfig.get("smtp_starttls").getAsBoolean();
            }

            if (jConfig.has("internal_mailer")) {
                JsonObject jMailer = jConfig.get("internal_mailer").getAsJsonObject();
                mInternalMailUser = jMailer.get("internal_mail_user").getAsString();
                mInternalMailPassword = jMailer.get("internal_mail_user_password").getAsString();
                if (jMailer.has("smtp_host")) {
                    mInternalMailSmtpHost = jMailer.get("smtp_host").getAsString();
                }
                if (jMailer.has("smtp_port")) {
                    mInternalMailSmtpPort = jMailer.get("smtp_port").getAsInt();
                }
                if (jMailer.has("starttls")) {
                    mInternalMailStartTls = jMailer.get("starttls").getAsBoolean();
                }
            }

            LOGGER.info("loaded configuration ({})", tConfigFilename);
            LOGGER.info("IMAP server: {}:{} (SSL: {})", mImapHost, mImapPort, mImapSsl);
            LOGGER.info("Messages batch size: {}", mMessagesBatchSize);

            mImapWebApi = new ImapRestApi(jConfig);

        } catch (IOException e) {
            new RuntimeException(e);
        }
    }

    private void loadDB() {
        JsonObject jDatabase = jConfig.get("database").getAsJsonObject();
        JsonObject jDbConfig = jDatabase.get("configuration").getAsJsonObject();
        if (jDatabase.get("type").getAsString().contentEquals("sqlite3")) {
            db = new DBSqlite3(jDbConfig.get("db_file").getAsString());
            db.connect();
            LOGGER.info("Conneted to sqlite3 database \"{}\"", jDbConfig.get("db_file").getAsString());
        } else {
          throw new RuntimeException("Database type \"" + jDatabase.get("type").getAsString() + "\" is not supported ");
        }
    }

    private void loadSasl() {
        if (jConfig.has("dovecot_sasl")) {
            JsonObject jSasl = jConfig.get("dovecot_sasl").getAsJsonObject();
            if (jSasl.has("enabled") && jSasl.get("enabled").getAsBoolean()) {
                int port = jSasl.get("port").getAsInt();
                String bindAddress = jSasl.get("bind_address").getAsString();
                mSaslServer = new DovecotSaslServer(port, bindAddress, db);

                // Register internal mailer user for SASL auth if SMTP goes through localhost
                if (mInternalMailUser != null && isLocalSmtpHost(mInternalMailSmtpHost)) {
                    mSaslServer.addServiceUser(mInternalMailUser, mInternalMailPassword);
                    LOGGER.info("Registered internal mailer user '{}' for Dovecot SASL", mInternalMailUser);
                }

                try {
                    mSaslServer.start();
                } catch (IOException e) {
                    LOGGER.warn("Failed to start Dovecot SASL server: {}", e.getMessage());
                }
            }
        }
    }

    static HashMap<String,String> paramsToMap(Context ctx ) {
        HashMap<String,String> tMap = new HashMap<>();

        if (ctx.method().toString().equals("GET")) {
            ctx.pathParamMap();
        } else  if (ctx.method().toString().equals("POST")) {
            String jString = ctx.body();
            JsonObject jParams = JsonParser.parseString( jString ).getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : jParams.entrySet()) {
                tMap.put(entry.getKey(), entry.getValue().getAsString());
            }
        }
        return tMap;

    }

    /** ====================================================================================
     * Define server entry points
     *
     * ===================================================================================
     */




    private static  void testPostS( Context ctx ) {
       sInstance.testPost(ctx );
    }
    private void testPost( Context ctx ) {
        String sessionId = ctx.req().getSession().getId();
        String rqstJson = ctx.body();

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm.ss.SSS");

        JsonObject jResponse = new JsonObject();
        jResponse.addProperty("sessionId", ctx.req().getSession().getId());
        jResponse.addProperty("time", simpleDateFormat.format( System.currentTimeMillis()));
        jResponse.addProperty("request", rqstJson);
        ctx.status(200).contentType("application/json").result(jResponse.toString());
    }


    public static void loginS(Context ctx) {
        sInstance.login(ctx);
    }

    private void login(Context ctx) {
        String contentType = ctx.contentType();
        if (!"application/json".equalsIgnoreCase(contentType)) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid content type, expected application/json"));
            return;
        }

        Map<String, String> tParams;
        try {
            tParams = paramsToMap(ctx);
        } catch (Exception e) {
            ctx.status(400).result(JAux.statusResponse(400, "Invalid JSON request"));
            return;
        }

        if (!tParams.containsKey(Profile.USERNAME)) {
            ctx.status(400).result(JAux.statusResponse(400, "Required parameter \"" + Profile.USERNAME + "\" is missing"));
            return;
        }

        if (!tParams.containsKey(Profile.PASSWORD)) {
            ctx.status(400).result(JAux.statusResponse(400, "Required parameter \"" + Profile.PASSWORD + "\" is missing"));
            return;
        }

        String username = tParams.get(Profile.USERNAME);
        String password = tParams.get(Profile.PASSWORD);

        // Check if an Admin user
        if (username.compareToIgnoreCase("admin") == 0) {
            try {
                JsonObject jAdmin = jConfig.get("admin").getAsJsonObject();
                String tAdminPassword = jAdmin.get("password").getAsString();

                // Check if there are any IP restrictions

                if (!IpMatcher.matches(ctx.ip(), jAdmin.get("allowed_hosts").getAsJsonArray())) {
                    LOGGER.warn("Admin is unauthorized from host: " + ctx.ip());
                    ctx.status(401).result(JAux.statusResponse(401, "Admin is authorized from host: " + ctx.ip()));
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                    }
                    return;
                }

                String tAdminHashedPassword = JAux.PBKDF2(username, tAdminPassword);

                if (tAdminHashedPassword.equals(password)) {
                    ctx.req().getSession().setAttribute("username", jAdmin);
                    ctx.req().getSession().setAttribute("role", "admin");
                    ctx.status(200).result(JAux.statusResponse(200, "Login successful"));
                } else {
                    ctx.status(401).result(JAux.statusResponse(401, "Invalid username or password"));
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                    }
                }
            }
            catch( Exception e) {
                LOGGER.warn("Login failed for user \"{}\": {}", username, e.getMessage());
                ctx.status(500).result(JAux.statusResponse(500, "Internal server error"));
            }
        } else {
            try {
                JsonObject jUser = db.findUser(username.toLowerCase());
                if (jUser == null) {
                    ctx.status(401).result(JAux.statusResponse(401, "Invalid username or password"));
                    return;
                }

                String storedPassword = jUser.get(Profile.PASSWORD).getAsString();
                if (!storedPassword.equals(password)) {
                    ctx.status(401).result(JAux.statusResponse(401, "Invalid username or password"));
                    return;
                }

                // Check if the user has confirmed, if nor reject the login
                if (!jUser.get(Profile.CONFIRMED).getAsBoolean()) {
                    ctx.status(401).result(JAux.statusResponse(401, "Account must be confirmed before login"));
                    return;
                }

                db.updateLastSeen(username);
                ctx.req().getSession().setAttribute("username", jUser);
                ctx.req().getSession().setAttribute("role","user");

                // Create IMAP session for the user
                Store imapStore = createImapSession(username, password);
                if (imapStore != null) {
                    ctx.req().getSession().setAttribute("imap_session", imapStore);
                }

                LOGGER.info("User \"{}\" logged in successfully", username);
                ctx.status(200).result(JAux.statusResponse(200, "Login successful"));

            } catch (DBException e) {
                LOGGER.warn("Login failed for user \"{}\": {}", username, e.getMessage());
                ctx.status(500).result(JAux.statusResponse(500, "Internal server error"));
            }
        }
    }

    public static void getUsersS(Context ctx) {
        sInstance.getUsers(ctx);
    }

    private void getUsers(Context ctx) {
        try {
            JsonArray credentials = db.findAllUserCredentials();
            JsonArray users = new JsonArray();

            if (credentials != null) {
                for (JsonElement elem : credentials) {
                    JsonObject cred = elem.getAsJsonObject();
                    String login = cred.get(Profile.USERNAME).getAsString();

                    JsonObject user = new JsonObject();
                    user.addProperty("email", login + "@" + mMailDomain);
                    user.addProperty("login", login);
                    user.addProperty("password", cred.get(Profile.PASSWORD).getAsString());
                    users.add(user);
                }
            }

            JsonObject response = new JsonObject();
            response.add("users", users);
            ctx.status(200).contentType("application/json").result(response.toString());
        } catch (DBException e) {
            LOGGER.warn("Failed to get users: {}", e.getMessage());
            ctx.status(500).contentType("application/json").result(JAux.statusResponse(500, "Failed to retrieve users"));
        }
    }

    private void declare() {
        // General before handler - runs for all requests
        mApp.before(ctx -> {
            LOGGER.info("{} {}", ctx.method(), ctx.path());
        });

        // Before handler for /api/* - does not a specific authorization, however the request must come from a
        // host that local or under control.
        mApp.before("/api/*", ctx -> {
            JsonObject jAdmin = jConfig.get("admin").getAsJsonObject();
            if (!IpMatcher.matches( ctx.ip(), jAdmin.get("allowed_hosts").getAsJsonArray() )) {
                throw new HttpResponseException(401, "Not authenticated");
            }
        });

        // Before handler for /admin/* - requires authentication
        mApp.before("/admin/*", ctx -> {
            JsonObject jUser = (JsonObject) ctx.req().getSession().getAttribute("username");
            if (jUser == null) {
                throw new HttpResponseException(401, "Not authenticated");
            }
        });

        // Before handler for /web/* - requires authentication
        mApp.before("/web/*", ctx -> {
            Object user = ctx.req().getSession().getAttribute("username");
            if (user == null) {
                throw new HttpResponseException(401, "Not authenticated");
            }
        });

        // Admin handler for user management
        mAdminHandler = new AdminHandler(db, mBaseUrl, mMailDomain, mAllowRegistration,
                mInternalMailUser, mInternalMailPassword, mInternalMailSmtpHost, mInternalMailSmtpPort, mInternalMailStartTls);

        // Public endpoints
        mApp.post("/tstpost", Server::testPostS);
        mApp.post("/register", ctx -> mAdminHandler.createUser(ctx));
        mApp.post("/login", Server::loginS);
        mApp.post("/confirm", ctx -> sInstance.confirmAccount(ctx));
        mApp.get("/decrypt-message", ctx -> sInstance.getDecryptMessage(ctx));

        // API endpoints (requires authentication)
        mApp.get("/api/users", Server::getUsersS);
        mApp.get("/api/admin", ctx -> getAdmin(ctx));

        // Admin endpoints
        mApp.post("/admin/users", ctx -> mAdminHandler.listUsers(ctx));
        mApp.post("/admin/handleUser", ctx -> mAdminHandler.handleUser(ctx));
        mApp.post("/admin/createUser", ctx -> mAdminHandler.adminCreateUser(ctx));

        // IMAP Admin endpoints (proxy to IMAP REST API)
        mApp.get("/admin/imap/users", ctx -> {
            String result = mImapWebApi.getUsers();
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });
        mApp.get("/admin/imap/domains", ctx -> {
            String result = mImapWebApi.getDomains();
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });
        mApp.get("/admin/imap/mailboxes", ctx -> {
            String userName = ctx.queryParam("user");
            if (userName == null || userName.isEmpty()) {
                ctx.status(400).result(JAux.statusResponse(400, "Missing user parameter"));
                return;
            }
            String result = mImapWebApi.getUserMailboxes(userName);
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });
        mApp.get("/admin/imap/mailQueues", ctx -> {
            String result = mImapWebApi.getMailQueues();
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });
        mApp.get("/admin/imap/mailRepositories", ctx -> {
            String result = mImapWebApi.getMailRepositories();
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });
        mApp.get("/admin/imap/deadLetters", ctx -> {
            String result = mImapWebApi.getDeadLetterGroups();
            if (result != null) {
                ctx.status(200).contentType("application/json").result(result);
            } else {
                ctx.status(502).result(JAux.statusResponse(502, "Failed to reach IMAP server"));
            }
        });

        // Web API endpoints (requires authentication)
        mWebHandler = new WebHandler(mMessagesBatchSize, mSmtpHost, mSmtpPort, mSmtpStartTls, mMailDomain);
        mApp.get("/web/mailboxes", ctx -> mWebHandler.listMailboxes(ctx));
        mApp.get("/web/messages", ctx -> mWebHandler.listMessages(ctx));
        mApp.get("/web/message", ctx -> mWebHandler.getMessage(ctx));
        mApp.get("/web/attachment", ctx -> mWebHandler.getAttachment(ctx));
        mApp.post("/web/compose/send", ctx -> mWebHandler.sendMessage(ctx));
        mApp.post("/web/message/delete", ctx -> mWebHandler.deleteMessage(ctx));

        // Profile endpoint — returns encrypted private key for client-side PGP decryption
        mApp.get("/web/profile", ctx -> {
            JsonObject jUser = (JsonObject) ctx.req().getSession().getAttribute("username");
            if (jUser == null) {
                ctx.status(401).result(JAux.statusResponse(401, "Not authenticated"));
                return;
            }
            JsonObject profile = new JsonObject();
            profile.addProperty(Profile.PRIVATE_KEY, jUser.get(Profile.PRIVATE_KEY).getAsString());
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(profile));
        });

        // Contact endpoints
        ContactHandler contactHandler = new ContactHandler(db);
        mApp.get("/web/contacts", ctx -> contactHandler.listContacts(ctx));
        mApp.post("/web/contacts/create", ctx -> contactHandler.createContact(ctx));
        mApp.post("/web/contacts/update", ctx -> contactHandler.updateContact(ctx));
        mApp.post("/web/contacts/delete", ctx -> contactHandler.deleteContact(ctx));
    }

    private void run() {
        mApp.start();
    }

    private void loadApp() {
        int port = 0;
        boolean tFlag = false;

        if (jConfig.has("http_port")) {
            JsonElement jsonElement = jConfig.get("http_port");
            if (!jsonElement.isJsonNull()) {
                tFlag = true;
                port = jsonElement.getAsInt();
            }
        }

        final boolean tInsecurePort = tFlag;
        final int https_port = jConfig.get("https_port").getAsInt();
        final int http_port = port;

        JsonObject jSsl = jConfig.get("ssl").getAsJsonObject();
        String sslCert = jSsl.get("cert").getAsString();
        String sslKey  = jSsl.get("key").getAsString();
        LOGGER.info("SSL cert: {}, key: {}", sslCert, sslKey);

        SslPlugin sslPlugin = new SslPlugin(conf -> {
            conf.pemFromPath(sslCert, sslKey);
            conf.insecure=tInsecurePort;
            conf.http2=true;
            conf.sniHostCheck=false;
            conf.securePort=https_port;
            conf.insecurePort=http_port;
        });


        mApp = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.registerPlugin(sslPlugin);
            config.staticFiles.add(staticFiles -> {
                staticFiles.directory = jConfig.get("web_content").getAsString(); // relative or absolute path
                staticFiles.location = Location.EXTERNAL;
            });
            config.jsonMapper(new JavalinJackson());
            config.jetty.modifyServletContextHandler(handler -> {
                SessionHandler sessionHandler = new SessionHandler();
                sessionHandler.setMaxInactiveInterval(10 * 60); // 10 minutes timeout
                sessionHandler.setHttpOnly(true);
                handler.setSessionHandler(sessionHandler);
            });
        });
    }



    private void confirmAccount(Context ctx) {
        String body = ctx.body();
        if (body == null || body.isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing request body"));
            return;
        }

        JsonObject jBody = JsonParser.parseString(body).getAsJsonObject();
        if (!jBody.has("uid")) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing uid parameter"));
            return;
        }

        String uid = jBody.get("uid").getAsString();
        try {
            JsonObject user = db.findUserByConfUid(uid);
            if (user == null) {
                ctx.status(404).result(JAux.statusResponse(404, "Invalid or expired confirmation link"));
                return;
            }

            if (user.get(Profile.CONFIRMED).getAsBoolean()) {
                ctx.status(200).result(JAux.statusResponse(200, "Account is already confirmed"));
                return;
            }

            db.confirmUser(uid);
            LOGGER.info("Account confirmed for user: {}", user.get(Profile.USERNAME).getAsString());
            ctx.status(200).result(JAux.statusResponse(200, "Account confirmed successfully. You can now log in."));
        } catch (DBException e) {
            LOGGER.warn("Failed to confirm account: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Failed to confirm account"));
        }
    }

    private void getDecryptMessage(Context ctx) {
        String uid = ctx.queryParam("uid");
        if (uid == null || uid.trim().isEmpty()) {
            ctx.status(400).result(JAux.statusResponse(400, "Missing uid parameter"));
            return;
        }

        try {
            JsonObject message = db.findDecryptMessage(uid.trim());
            if (message == null) {
                ctx.status(404).result(JAux.statusResponse(404, "Message not found"));
                return;
            }
            ctx.status(200).contentType("application/json").result(JAux.statusResponse(message));
        } catch (DBException e) {
            LOGGER.warn("Failed to find decrypt message: {}", e.getMessage());
            ctx.status(500).result(JAux.statusResponse(500, "Internal server error"));
        }
    }

    private boolean isLocalSmtpHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
    }

    public static String getImapHost() {
        return sInstance.mImapHost;
    }

    public static int getImapPort() {
        return sInstance.mImapPort;
    }

    /**
     * Create an SSLSocketFactory that trusts all certificates.
     * For testing/development use only.
     */
    private SSLSocketFactory createTrustAllSocketFactory() {
        try {
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
            LOGGER.warn("Failed to create trust-all SSLSocketFactory: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Create and connect an IMAP session for the given user.
     *
     * @param username The IMAP username
     * @param password The IMAP password
     * @return Connected Store object, or null if connection failed
     */
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
            if ((System.getProperty("imap_user") != null) && (System.getProperty("imap_password") != null)) {
                store.connect(mImapHost, mImapPort, System.getProperty("imap_user") , System.getProperty("imap_password"));
            } else {
                store.connect(mImapHost, mImapPort, username, password);
            }
            LOGGER.info("IMAP session created for user: {} (SSL: {})", username, mImapSsl);
            return store;
        } catch (MessagingException e) {
            LOGGER.warn("Failed to create IMAP session for user {}: {}", username, e.getMessage());
            return null;
        }
    }

    private void getAdmin(Context ctx) {
        JsonObject jAdmin = jConfig.get("admin").getAsJsonObject();
        JsonObject response = new JsonObject();
        response.addProperty("user", "admin");
        response.addProperty("password", jAdmin.get("password").getAsString());
        ctx.status(200).contentType("application/json").result(response.toString());
    }

    private void loadAfterQueueFilter() {
        if (!jConfig.has("postfix_after_queue")) return;

        JsonObject jAfterQueue = jConfig.get("postfix_after_queue").getAsJsonObject();
        if (!jAfterQueue.has("enabled") || !jAfterQueue.get("enabled").getAsBoolean()) return;

        int port        = jAfterQueue.get("port").getAsInt();
        int requeuePort = jAfterQueue.get("requeue_port").getAsInt();
        new PostfixAfterQueueFilter(jConfig, port, requeuePort);
        LOGGER.info("Postfix after-queue filter started (listen={}, requeue={})", port, requeuePort);
    }

    public static void main(String[] args) {
        sInstance = new Server();
            sInstance.logStartupInfo();
            sInstance.loadConfig( args );
            sInstance.loadDB();
            sInstance.loadSasl();
            sInstance.loadAfterQueueFilter();
            sInstance.loadApp();
            sInstance.declare();
            sInstance.run();
    }
}
