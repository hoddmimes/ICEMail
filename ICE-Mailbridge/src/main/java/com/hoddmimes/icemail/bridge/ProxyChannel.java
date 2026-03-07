/**
 * A communication channel between an IMAP server that only accepts secure connections, 
 * and a client that does not support emails over secure connections.
 */

package com.hoddmimes.icemail.bridge;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.Level;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class ProxyChannel implements Runnable
{
	private static final String NEW_LINE = "\r\n";

	// Pattern to match IMAP LOGIN command: <tag> LOGIN <username> <password>
	private static final Pattern LOGIN_PATTERN = Pattern.compile(
		"^(\\S+)\\s+LOGIN\\s+(\\S+)\\s+(\\S+)\\s*$", Pattern.CASE_INSENSITIVE);

	// Pattern to match IMAP AUTHENTICATE PLAIN with optional initial response (SASL-IR)
	private static final Pattern AUTH_PLAIN_PATTERN = Pattern.compile(
		"^(\\S+)\\s+AUTHENTICATE\\s+PLAIN(?:\\s+(\\S+))?\\s*$", Pattern.CASE_INSENSITIVE);

	// State for two-step AUTHENTICATE PLAIN (when client sends credentials on the next line)
	private volatile String mPendingAuthTag = null;

	// Configuration
	private final BridgeConfiguration config;

	private Socket plainSocket = null;
	private BufferedReader plainBufferedReader = null;
	private OutputStream plainOutputStream = null;

	private SSLSocketFactory sslSocketFactory = null;
	private SSLSocket sslSocket = null;
	private SSLSession sslSession = null;
	private BufferedReader sslBufferedReader = null;
	private OutputStream sslOutputStream = null;

	// Decryption components
	private final Decryptor decryptor;
	private final ImapResponseHandler responseHandler;

	// Login handler
	private final LoginHandler loginHandler;

	/**
	 * Create a proxy channel with default configuration.
	 */
	public ProxyChannel( Socket plainSocket)
	{
		this( plainSocket, new BridgeConfiguration(), new PassthroughLoginHandler());
	}

	/**
	 * Create a proxy channel with configuration and login handler.
	 * A new Decryptor instance is created per session from the configuration.
	 *
	 * @param plainSocket  The client socket
	 * @param config       The bridge configuration
	 * @param loginHandler The login handler implementation to use
	 */
	public ProxyChannel( Socket plainSocket, BridgeConfiguration config, LoginHandler loginHandler)
	{
		this.plainSocket = plainSocket;
		this.config = config;
		this.decryptor = config.createDecryptor();
		this.responseHandler = new ImapResponseHandler( this.decryptor);
		this.loginHandler = loginHandler;

		// Initialize SSL socket factory with configured protocol
		initializeSslSocketFactory();
	}

	private void initializeSslSocketFactory()
	{
		try {
			SSLContext sslContext = SSLContext.getInstance( config.getTlsProtocol());
			sslContext.init( null, new X509TrustManager[]{ new CustomTrustManager() }, new SecureRandom());
			sslSocketFactory = sslContext.getSocketFactory();
		} catch( NoSuchAlgorithmException e) {
			MailBridge.log( Level.ERROR, "TLS protocol not supported: " + config.getTlsProtocol(), e);
		} catch( KeyManagementException e) {
			MailBridge.log( Level.ERROR, "Failed to initialize SSL context", e);
		}
	}

	/**
	 * Process a command from the client, intercepting LOGIN and AUTHENTICATE PLAIN commands.
	 *
	 * @param command The command line from the client
	 * @return The (possibly modified) command to send to server, or null if blocked
	 */
	private String processClientCommand( String command)
	{
		MailBridge.log( Level.TRACE, "Raw client command: [" + command + "]");

		// Check if we're waiting for the continuation line of a two-step AUTHENTICATE PLAIN
		if( mPendingAuthTag != null)
		{
			String tag = mPendingAuthTag;
			mPendingAuthTag = null;
			return handleAuthPlainData( tag, command.trim(), false);
		}

		Matcher loginMatcher = LOGIN_PATTERN.matcher( command);
		if( loginMatcher.matches())
		{
			return handleLoginCommand( command, loginMatcher);
		}

		Matcher authMatcher = AUTH_PLAIN_PATTERN.matcher( command);
		if( authMatcher.matches())
		{
			return handleAuthenticatePlain( command, authMatcher);
		}

		// Not a LOGIN or AUTHENTICATE command, pass through unchanged
		return command;
	}

	/**
	 * Handle an IMAP AUTHENTICATE PLAIN command.
	 * If the initial response is included (SASL-IR), process it immediately.
	 * Otherwise, forward the command to the server and wait for the continuation.
	 */
	private String handleAuthenticatePlain( String originalCommand, Matcher matcher)
	{
		String tag = matcher.group(1);
		String initialResponse = matcher.group(2);

		if( initialResponse != null)
		{
			// SASL-IR: credentials included in the AUTHENTICATE line
			MailBridge.log( Level.DEBUG, "Intercepted AUTHENTICATE PLAIN (SASL-IR) command");
			return handleAuthPlainData( tag, initialResponse, true);
		}

		// Two-step: forward command to server, it will send "+", then client sends base64
		MailBridge.log( Level.DEBUG, "Intercepted AUTHENTICATE PLAIN command, waiting for credentials");
		mPendingAuthTag = tag;
		return originalCommand;
	}

	/**
	 * Decode SASL PLAIN base64 data, invoke the login handler, and re-encode.
	 * PLAIN format: authzid\0username\0password
	 *
	 * @param tag The IMAP command tag
	 * @param base64Data The base64-encoded SASL PLAIN credentials
	 * @param isSaslIR true if this is a SASL-IR (single-line), false if two-step continuation
	 */
	private String handleAuthPlainData( String tag, String base64Data, boolean isSaslIR)
	{
		try {
			byte[] decoded = Base64.getDecoder().decode( base64Data);
			String plainStr = new String( decoded, StandardCharsets.UTF_8);

			// Split on null bytes: authzid\0username\0password
			int first = plainStr.indexOf('\0');
			int second = plainStr.indexOf('\0', first + 1);
			if( first < 0 || second < 0)
			{
				MailBridge.log( Level.WARN, "Invalid AUTHENTICATE PLAIN data format");
				return isSaslIR ? (tag + " AUTHENTICATE PLAIN " + base64Data) : base64Data;
			}

			String authzid = plainStr.substring( 0, first);
			String username = plainStr.substring( first + 1, second);
			String plaintextPassword = plainStr.substring( second + 1);

			MailBridge.log( Level.DEBUG, "AUTHENTICATE PLAIN decoded - authzid: [" + authzid + "] username: [" + username + "] password-length: " + plaintextPassword.length());
			MailBridge.log( Level.DEBUG, "Intercepted AUTHENTICATE PLAIN for user: " + username);

			LoginHandler.LoginResult result = loginHandler.executeLogin( username, plaintextPassword);

			if( result.isBlocked())
			{
				MailBridge.log( Level.WARN, "AUTHENTICATE PLAIN blocked for user " + username + ": " + result.getBlockReason());
				try {
					if( !isSaslIR) {
						// Two-step: cancel the server's continuation
						sslOutputStream.write( ("*" + NEW_LINE).getBytes());
					}
					String noResponse = tag + " NO " + result.getBlockReason() + NEW_LINE;
					plainOutputStream.write( noResponse.getBytes());
				} catch( IOException e) {
					MailBridge.log( Level.ERROR, "Failed to send blocked auth response", e);
				}
				return null;
			}

			// Initialize the per-session decryptor with the encrypted private key and plaintext password
			if( result.getEncryptedPrivateKey() != null)
			{
				MailBridge.log( Level.DEBUG, "Initializing decryptor for user: " + username);
				decryptor.initialize( result.getEncryptedPrivateKey(), plaintextPassword);
				MailBridge.log( Level.DEBUG, "Decryptor initialization complete for user: " + username);
			}
			else
			{
				MailBridge.log( Level.WARN, "No encrypted private key returned for user: " + username + ", decryption will be disabled");
			}

			String finalUsername = result.isModified() ? result.getUsername() : username;
			String finalPassword = result.isModified() ? result.getPassword() : plaintextPassword;

			// Re-encode as SASL PLAIN: authzid\0username\0password
			String newPlain = authzid + "\0" + finalUsername + "\0" + finalPassword;
			String newBase64 = Base64.getEncoder().encodeToString( newPlain.getBytes( StandardCharsets.UTF_8));

			MailBridge.log( Level.DEBUG, "Forwarding modified AUTHENTICATE PLAIN credentials to IMAP server for user: " + finalUsername);

			if( isSaslIR)
			{
				return tag + " AUTHENTICATE PLAIN " + newBase64;
			}

			// Two-step continuation: return just the base64 data
			return newBase64;
		} catch( Exception e) {
			MailBridge.log( Level.ERROR, "Failed to process AUTHENTICATE PLAIN data", e);
			return isSaslIR ? (tag + " AUTHENTICATE PLAIN " + base64Data) : base64Data;
		}
	}

	/**
	 * Handle an IMAP LOGIN command by calling the login handler.
	 * The plaintext password is captured before hashing so the decryptor can unlock the private key.
	 *
	 * @param originalCommand The original LOGIN command
	 * @param matcher The regex matcher with captured groups
	 * @return The (possibly modified) LOGIN command, or null if blocked
	 */
	private String handleLoginCommand( String originalCommand, Matcher matcher)
	{
		String tag = matcher.group(1);
		String username = matcher.group(2);
		String plaintextPassword = matcher.group(3);

		MailBridge.log( Level.DEBUG, "Intercepted LOGIN command - tag: [" + tag + "] username: [" + username + "] password-length: " + plaintextPassword.length());

		// Call the login handler (hashes password, fetches encrypted private key from server)
		LoginHandler.LoginResult result = loginHandler.executeLogin( username, plaintextPassword);

		if( result.isBlocked())
		{
			MailBridge.log( Level.WARN, "Login blocked for user " + username + ": " + result.getBlockReason());
			try {
				String noResponse = tag + " NO " + result.getBlockReason() + NEW_LINE;
				plainOutputStream.write( noResponse.getBytes());
			} catch( IOException e) {
				MailBridge.log( Level.ERROR, "Failed to send blocked login response", e);
			}
			return null;
		}

		// Initialize the per-session decryptor with the encrypted private key and plaintext password
		if( result.getEncryptedPrivateKey() != null)
		{
			MailBridge.log( Level.DEBUG, "Initializing decryptor for user: " + username);
			decryptor.initialize( result.getEncryptedPrivateKey(), plaintextPassword);
			MailBridge.log( Level.DEBUG, "Decryptor initialization complete for user: " + username);
		}
		else
		{
			MailBridge.log( Level.WARN, "No encrypted private key returned for user: " + username + ", decryption will be disabled");
		}

		if( result.isModified())
		{
			MailBridge.log( Level.DEBUG, "Login credentials modified for user: " + username);
			return result.toImapCommand( tag);
		}

		return originalCommand;
	}
	
	@Override
	public void run()
	{
		String imapHost = config.getImapHost();
		int imapPort = config.getImapPort();
		String clientAddr = plainSocket.getInetAddress().getHostAddress() + ":" + plainSocket.getPort();

		try {
			MailBridge.log( Level.INFO, "Client connected from " + clientAddr);
			MailBridge.log( Level.INFO, "Connecting to IMAP server " + imapHost + ":" + imapPort);

			// Establish a secure connection to the email server
			sslSocket = (SSLSocket) sslSocketFactory.createSocket( imapHost, imapPort);

			// Disable hostname verification to accept any certificate
			javax.net.ssl.SSLParameters sslParams = sslSocket.getSSLParameters();
			sslParams.setEndpointIdentificationAlgorithm(null);
			sslSocket.setSSLParameters(sslParams);

			sslSocket.startHandshake();
			sslSession = sslSocket.getSession();

			String[] protocols = sslSocket.getEnabledProtocols();
			for( int i = 0; i < protocols.length; i++)
				MailBridge.log( Level.DEBUG, protocols[i]);

			Certificate[] certificateChain = sslSession.getPeerCertificates();

			MailBridge.log( Level.DEBUG, "The certificates used by peer");
			for( int i = 0; i < certificateChain.length; i++)
				MailBridge.log( Level.DEBUG, ((X509Certificate) certificateChain[i]).getSubjectDN().toString());

			MailBridge.log( Level.INFO, "Successfully connected to IMAP server " + imapHost + ":" + imapPort + " (TLS: " + sslSession.getProtocol() + ")");
			
			// Create input and output streams between proxy and server
			sslBufferedReader = new BufferedReader( new InputStreamReader( sslSocket.getInputStream()));
			sslOutputStream = sslSocket.getOutputStream();

			MailBridge.log( Level.INFO, "Starting to listen");

			// Create input and output streams between proxy and client
			plainBufferedReader = new BufferedReader( new InputStreamReader( plainSocket.getInputStream()));
			plainOutputStream = plainSocket.getOutputStream();
			
			Thread[] threads = new Thread[2];
			
			// Create a thread for listening to messages from server and forwarding them to client
			threads[0] = new Thread( new Runnable()
				{
					public void run()
					{
						String sslInputLine = null;
						try {
							// Listen to messages from server
							while(( sslInputLine = sslBufferedReader.readLine()) != null)
							{
								// Process through IMAP response handler for potential decryption
								String processedLine = responseHandler.processServerResponse( sslInputLine);

								// If handler returns null, it's buffering a multi-line response
								if( processedLine != null)
								{
									// readLine loses line separator, re-add it.
									processedLine = processedLine + NEW_LINE;
									plainOutputStream.write( processedLine.getBytes());
									MailBridge.log( Level.TRACE, "From server to client: " + processedLine);
								}
							}
						} catch( IOException e) {
							MailBridge.log( Level.ERROR, e.toString(), e);
						}
					}
				}
			);

			// Create a thread for listening to messages from client and forwarding them to server
			threads[1] = new Thread( new Runnable()
				{
					public void run()
					{
						String plainInputLine = null;
						try {
							// Listen to messages from client
							while(( plainInputLine = plainBufferedReader.readLine()) != null)
							{
								// Process through command handler for potential LOGIN interception
								String processedLine = processClientCommand( plainInputLine);

								// If handler returns null, the command was blocked
								if( processedLine != null)
								{
									// readLine loses line separator, re-add it.
									processedLine = processedLine + NEW_LINE;
									sslOutputStream.write( processedLine.getBytes());
									MailBridge.log( Level.TRACE, "From client to server: " + processedLine);
								}
							}
						} catch( IOException e) {
							MailBridge.log( Level.ERROR, e.toString(), e);
						}
					}
				}
			);
			
			// Start both threads
			for( Thread thread : threads)
				thread.start();
			
			// Wait until both threads end
			for( Thread thread : threads)
				thread.join();
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, e.toString(), e);
		} catch( InterruptedException e) {
			MailBridge.log( Level.ERROR, e.toString(), e);
		} finally {
			try {
				if( sslSocket != null)
					sslSocket.close();
			} catch( IOException e) {
				MailBridge.log( Level.ERROR, e.toString(), e);
			}
			
			try {
				if( plainSocket != null)
					plainSocket.close();
			} catch( IOException e) {
				MailBridge.log( Level.ERROR, e.toString(), e);
			}
		}
	}
}
