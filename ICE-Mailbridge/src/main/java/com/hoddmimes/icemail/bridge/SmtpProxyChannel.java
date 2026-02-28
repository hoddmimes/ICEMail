/**
 * SMTP submission proxy channel.
 * Sits between a mail client and an SMTP server, intercepting AUTH commands
 * to hash passwords (via LoginHandler) before forwarding to the server.
 * Supports STARTTLS on both client-facing and server-facing sides.
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
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.Level;

public class SmtpProxyChannel implements Runnable
{
	private static final String CRLF = "\r\n";

	private final Socket clientSocket;
	private final BridgeConfiguration config;
	private final LoginHandler loginHandler;

	// Server-side connection (to upstream SMTP server)
	private Socket serverSocket;
	private BufferedReader serverReader;
	private OutputStream serverOut;

	// Client-side connection (from mail client)
	private BufferedReader clientReader;
	private OutputStream clientOut;

	// SSLSocketFactory for connecting to the upstream SMTP server (trust-all)
	private SSLSocketFactory serverSslFactory;

	public SmtpProxyChannel( Socket clientSocket, BridgeConfiguration config, LoginHandler loginHandler)
	{
		this.clientSocket = clientSocket;
		this.config = config;
		this.loginHandler = loginHandler;
		initializeServerSslFactory();
	}

	private void initializeServerSslFactory()
	{
		try {
			SSLContext ctx = SSLContext.getInstance( config.getTlsProtocol());
			ctx.init( null, new X509TrustManager[]{ new CustomTrustManager() }, new SecureRandom());
			serverSslFactory = ctx.getSocketFactory();
		} catch( NoSuchAlgorithmException | KeyManagementException e) {
			MailBridge.log( Level.ERROR, "Failed to initialize SMTP server SSL factory", e);
		}
	}

	@Override
	public void run()
	{
		try {
			// Connect to upstream SMTP server (plain TCP initially)
			serverSocket = new Socket( config.getSmtpHost(), config.getSmtpPort());
			serverReader = new BufferedReader( new InputStreamReader( serverSocket.getInputStream()));
			serverOut = serverSocket.getOutputStream();

			// Set up client-side streams
			clientReader = new BufferedReader( new InputStreamReader( clientSocket.getInputStream()));
			clientOut = clientSocket.getOutputStream();

			MailBridge.log( Level.INFO, "SMTP proxy connected to " + config.getSmtpHost() + ":" + config.getSmtpPort());

			// Read 220 greeting from SMTP server, forward to client
			String greeting = readSmtpResponse();
			sendToClient( greeting);

			// Enter command loop
			String line;
			while(( line = clientReader.readLine()) != null)
			{
				String cmd = line.trim();
				if( cmd.isEmpty())
				{
					continue;
				}

				String upperCmd = cmd.toUpperCase();
				MailBridge.log( Level.TRACE, "SMTP client: " + cmd);

				if( upperCmd.startsWith( "EHLO") || upperCmd.startsWith( "HELO"))
				{
					handleEhlo( cmd);
				}
				else if( upperCmd.equals( "STARTTLS"))
				{
					handleStarttls();
				}
				else if( upperCmd.startsWith( "AUTH PLAIN"))
				{
					handleAuthPlain( cmd);
				}
				else if( upperCmd.startsWith( "AUTH LOGIN"))
				{
					handleAuthLogin();
				}
				else if( upperCmd.equals( "DATA"))
				{
					handleData();
				}
				else if( upperCmd.equals( "QUIT"))
				{
					sendToServer( cmd);
					String resp = readSmtpResponse();
					sendToClient( resp);
					break;
				}
				else
				{
					// Pass through: MAIL FROM, RCPT TO, RSET, NOOP, etc.
					sendToServer( cmd);
					String resp = readSmtpResponse();
					sendToClient( resp);
				}
			}
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, "SMTP proxy error: " + e.toString(), e);
		} finally {
			close();
		}
	}

	/**
	 * Forward EHLO/HELO to server, relay multi-line response to client.
	 */
	private void handleEhlo( String cmd) throws IOException
	{
		sendToServer( cmd);
		String resp = readSmtpResponse();
		sendToClient( resp);
	}

	/**
	 * Handle STARTTLS: upgrade both server and client connections to TLS.
	 */
	private void handleStarttls() throws IOException
	{
		// Forward STARTTLS to the upstream SMTP server
		sendToServer( "STARTTLS");
		String serverResp = readSmtpResponse();

		if( !serverResp.startsWith( "220"))
		{
			// Server refused STARTTLS, relay error to client
			sendToClient( serverResp);
			return;
		}

		// Upgrade the server connection to TLS
		upgradeServerToTls();

		// Tell client we're ready for TLS
		sendToClient( "220 Ready to start TLS");

		// Upgrade client connection to TLS
		upgradeClientToTls();

		MailBridge.log( Level.INFO, "SMTP STARTTLS completed on both sides");
	}

	/**
	 * Handle AUTH PLAIN - single-line or two-step.
	 * Format: "AUTH PLAIN [base64]" or "AUTH PLAIN" followed by "334" then base64.
	 */
	private void handleAuthPlain( String cmd) throws IOException
	{
		String upperCmd = cmd.toUpperCase();
		String afterAuthPlain = cmd.substring( "AUTH PLAIN".length()).trim();

		if( !afterAuthPlain.isEmpty())
		{
			// Single-line AUTH PLAIN with initial response
			String result = processAuthPlainData( afterAuthPlain);
			if( result == null)
			{
				// Blocked - already sent error to client
				return;
			}
			sendToServer( "AUTH PLAIN " + result);
			String resp = readSmtpResponse();
			sendToClient( resp);
		}
		else
		{
			// Two-step: forward AUTH PLAIN to server, get 334 challenge
			sendToServer( cmd);
			String challenge = readSmtpResponse();
			if( !challenge.startsWith( "334"))
			{
				sendToClient( challenge);
				return;
			}
			sendToClient( challenge);

			// Read base64 credentials from client
			String base64Data = clientReader.readLine();
			if( base64Data == null)
			{
				return;
			}

			String result = processAuthPlainData( base64Data.trim());
			if( result == null)
			{
				// Blocked - send cancel to server
				sendToServer( "*");
				readSmtpResponse(); // consume server's error response
				return;
			}
			sendToServer( result);
			String resp = readSmtpResponse();
			sendToClient( resp);
		}
	}

	/**
	 * Handle AUTH LOGIN - multi-step challenge/response.
	 * Translates to AUTH PLAIN when forwarding to the SMTP server.
	 */
	private void handleAuthLogin() throws IOException
	{
		// Prompt for username (334 VXNlcm5hbWU6 = "Username:")
		sendToClient( "334 VXNlcm5hbWU6");

		String usernameB64 = clientReader.readLine();
		if( usernameB64 == null)
		{
			return;
		}
		String username = new String( Base64.getDecoder().decode( usernameB64.trim()), StandardCharsets.UTF_8);

		// Prompt for password (334 UGFzc3dvcmQ6 = "Password:")
		sendToClient( "334 UGFzc3dvcmQ6");

		String passwordB64 = clientReader.readLine();
		if( passwordB64 == null)
		{
			return;
		}
		String password = new String( Base64.getDecoder().decode( passwordB64.trim()), StandardCharsets.UTF_8);

		MailBridge.log( Level.DEBUG, "SMTP AUTH LOGIN for user: " + username);

		// Run through login handler
		LoginHandler.LoginResult result = loginHandler.executeLogin( username, password);

		if( result.isBlocked())
		{
			MailBridge.log( Level.WARN, "SMTP AUTH LOGIN blocked for user " + username + ": " + result.getBlockReason());
			sendToClient( "535 5.7.8 Authentication credentials invalid");
			return;
		}

		String finalUsername = result.isModified() ? result.getUsername() : username;
		String finalPassword = result.isModified() ? result.getPassword() : password;

		// Construct AUTH PLAIN and send to server
		String plain = "\0" + finalUsername + "\0" + finalPassword;
		String base64 = Base64.getEncoder().encodeToString( plain.getBytes( StandardCharsets.UTF_8));

		sendToServer( "AUTH PLAIN " + base64);
		String resp = readSmtpResponse();
		sendToClient( resp);
	}

	/**
	 * Handle DATA phase - relay lines until lone "." terminator.
	 */
	private void handleData() throws IOException
	{
		sendToServer( "DATA");
		String resp = readSmtpResponse();
		sendToClient( resp);

		if( !resp.startsWith( "354"))
		{
			return;
		}

		// Relay message body from client to server until lone "."
		String line;
		while(( line = clientReader.readLine()) != null)
		{
			sendToServer( line);
			if( line.equals( "."))
			{
				break;
			}
		}

		// Read final response (250 OK) from server
		resp = readSmtpResponse();
		sendToClient( resp);
	}

	/**
	 * Decode SASL PLAIN base64, hash password via loginHandler, re-encode.
	 * Returns the new base64 string, or null if blocked.
	 */
	private String processAuthPlainData( String base64Data) throws IOException
	{
		try {
			byte[] decoded = Base64.getDecoder().decode( base64Data);
			String plainStr = new String( decoded, StandardCharsets.UTF_8);

			// SASL PLAIN format: authzid\0username\0password
			int first = plainStr.indexOf( '\0');
			int second = plainStr.indexOf( '\0', first + 1);
			if( first < 0 || second < 0)
			{
				MailBridge.log( Level.WARN, "Invalid AUTH PLAIN data format");
				return base64Data;
			}

			String authzid = plainStr.substring( 0, first);
			String username = plainStr.substring( first + 1, second);
			String password = plainStr.substring( second + 1);

			MailBridge.log( Level.DEBUG, "SMTP AUTH PLAIN for user: " + username);

			LoginHandler.LoginResult result = loginHandler.executeLogin( username, password);

			if( result.isBlocked())
			{
				MailBridge.log( Level.WARN, "SMTP AUTH PLAIN blocked for user " + username + ": " + result.getBlockReason());
				sendToClient( "535 5.7.8 Authentication credentials invalid");
				return null;
			}

			String finalUsername = result.isModified() ? result.getUsername() : username;
			String finalPassword = result.isModified() ? result.getPassword() : password;

			String newPlain = authzid + "\0" + finalUsername + "\0" + finalPassword;
			return Base64.getEncoder().encodeToString( newPlain.getBytes( StandardCharsets.UTF_8));
		} catch( IllegalArgumentException e) {
			MailBridge.log( Level.WARN, "Failed to decode AUTH PLAIN base64 data", e);
			return base64Data;
		}
	}

	/**
	 * Read a potentially multi-line SMTP response.
	 * Multi-line responses have a hyphen as the 4th character (e.g., "250-STARTTLS").
	 * The last line has a space (e.g., "250 OK").
	 */
	private String readSmtpResponse() throws IOException
	{
		StringBuilder sb = new StringBuilder();
		String line;
		while(( line = serverReader.readLine()) != null)
		{
			if( sb.length() > 0)
			{
				sb.append( CRLF);
			}
			sb.append( line);

			// If line is shorter than 4 chars or 4th char is space (not hyphen), it's the last line
			if( line.length() < 4 || line.charAt( 3) != '-')
			{
				break;
			}
		}
		String resp = sb.toString();
		MailBridge.log( Level.TRACE, "SMTP server: " + resp);
		return resp;
	}

	/**
	 * Send a line to the client (with CRLF).
	 */
	private void sendToClient( String data) throws IOException
	{
		// Data may contain multiple CRLF-separated lines (from readSmtpResponse)
		clientOut.write( (data + CRLF).getBytes( StandardCharsets.UTF_8));
		clientOut.flush();
	}

	/**
	 * Send a line to the upstream SMTP server (with CRLF).
	 */
	private void sendToServer( String data) throws IOException
	{
		serverOut.write( (data + CRLF).getBytes( StandardCharsets.UTF_8));
		serverOut.flush();
	}

	/**
	 * Upgrade the server connection to TLS by wrapping the existing socket.
	 */
	private void upgradeServerToTls() throws IOException
	{
		SSLSocket sslSocket = (SSLSocket) serverSslFactory.createSocket(
			serverSocket, config.getSmtpHost(), config.getSmtpPort(), true);

		javax.net.ssl.SSLParameters sslParams = sslSocket.getSSLParameters();
		sslParams.setEndpointIdentificationAlgorithm( null);
		sslSocket.setSSLParameters( sslParams);

		sslSocket.startHandshake();

		serverSocket = sslSocket;
		serverReader = new BufferedReader( new InputStreamReader( sslSocket.getInputStream()));
		serverOut = sslSocket.getOutputStream();

		MailBridge.log( Level.DEBUG, "SMTP server connection upgraded to TLS");
	}

	/**
	 * Upgrade the client connection to TLS by wrapping the accepted socket as a server-side TLS socket.
	 * Uses the same PEM cert/key as the IMAPS listener.
	 */
	private void upgradeClientToTls() throws IOException
	{
		try {
			SSLContext sslContext = createClientFacingSslContext();

			SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
				clientSocket, clientSocket.getInetAddress().getHostAddress(), clientSocket.getPort(), true);
			sslSocket.setUseClientMode( false);
			sslSocket.startHandshake();

			clientReader = new BufferedReader( new InputStreamReader( sslSocket.getInputStream()));
			clientOut = sslSocket.getOutputStream();

			MailBridge.log( Level.DEBUG, "SMTP client connection upgraded to TLS");
		} catch( Exception e) {
			throw new IOException( "Failed to upgrade client connection to TLS", e);
		}
	}

	/**
	 * Create an SSLContext with the configured cert/key for client-facing TLS.
	 */
	private SSLContext createClientFacingSslContext() throws Exception
	{
		// Reuse the PEM loading from PemSslContextFactory approach
		java.security.cert.X509Certificate[] certChain = loadCertificateChain( config.getImapsCertPath());
		java.security.PrivateKey privateKey = loadPrivateKey( config.getImapsKeyPath());

		java.security.KeyStore keyStore = java.security.KeyStore.getInstance( "JKS");
		keyStore.load( null, null);
		keyStore.setKeyEntry( "smtpproxy", privateKey, "".toCharArray(), certChain);

		KeyManagerFactory kmf = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm());
		kmf.init( keyStore, "".toCharArray());

		SSLContext ctx = SSLContext.getInstance( config.getTlsProtocol());
		ctx.init( kmf.getKeyManagers(), null, null);
		return ctx;
	}

	/**
	 * Load certificate chain from PEM file (delegates to PemSslContextFactory pattern).
	 */
	private java.security.cert.X509Certificate[] loadCertificateChain( String certPath) throws Exception
	{
		java.util.List<java.security.cert.X509Certificate> certs = new java.util.ArrayList<>();
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance( "X.509");

		try( BufferedReader reader = new BufferedReader( new java.io.FileReader( certPath)))
		{
			StringBuilder certPem = new StringBuilder();
			boolean inCert = false;
			String line;
			while(( line = reader.readLine()) != null)
			{
				if( line.contains( "BEGIN CERTIFICATE"))
				{
					inCert = true;
					certPem = new StringBuilder();
				}
				else if( line.contains( "END CERTIFICATE"))
				{
					inCert = false;
					byte[] certBytes = Base64.getDecoder().decode( certPem.toString());
					certs.add( (java.security.cert.X509Certificate) cf.generateCertificate(
						new java.io.ByteArrayInputStream( certBytes)));
				}
				else if( inCert)
				{
					certPem.append( line.trim());
				}
			}
		}

		if( certs.isEmpty())
		{
			throw new IOException( "No certificates found in " + certPath);
		}
		return certs.toArray( new java.security.cert.X509Certificate[0]);
	}

	/**
	 * Load private key from PEM file (delegates to PemSslContextFactory pattern).
	 */
	private java.security.PrivateKey loadPrivateKey( String keyPath) throws Exception
	{
		StringBuilder keyPem = new StringBuilder();
		boolean inKey = false;

		try( BufferedReader reader = new BufferedReader( new java.io.FileReader( keyPath)))
		{
			String line;
			while(( line = reader.readLine()) != null)
			{
				if( line.contains( "BEGIN PRIVATE KEY") || line.contains( "BEGIN RSA PRIVATE KEY"))
				{
					inKey = true;
				}
				else if( line.contains( "END PRIVATE KEY") || line.contains( "END RSA PRIVATE KEY"))
				{
					inKey = false;
				}
				else if( inKey)
				{
					keyPem.append( line.trim());
				}
			}
		}

		if( keyPem.length() == 0)
		{
			throw new IOException( "No private key found in " + keyPath);
		}

		byte[] keyBytes = Base64.getDecoder().decode( keyPem.toString());
		java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec( keyBytes);

		try {
			return java.security.KeyFactory.getInstance( "RSA").generatePrivate( keySpec);
		} catch( Exception e) {
			return java.security.KeyFactory.getInstance( "EC").generatePrivate( keySpec);
		}
	}

	/**
	 * Close both client and server sockets.
	 */
	private void close()
	{
		try {
			if( serverSocket != null)
				serverSocket.close();
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, "Error closing SMTP server socket", e);
		}

		try {
			if( clientSocket != null)
				clientSocket.close();
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, "Error closing SMTP client socket", e);
		}
	}
}
