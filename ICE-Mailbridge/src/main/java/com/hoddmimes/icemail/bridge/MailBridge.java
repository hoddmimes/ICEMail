/**
 * ICE MailBridge - IMAP proxy between mail clients and encrypted IMAP server.
 * Sits between an IMAP client and an IMAP server, handling decryption and login processing.
 */

package com.hoddmimes.icemail.bridge;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MailBridge
{
	private static final Logger LOGGER = LogManager.getLogger( MailBridge.class);

	public static void main( String[] args)
	{
		// Load configuration
		String configFile = args.length > 0 ? args[0] : "mailbridge.json";
		BridgeConfiguration config = BridgeConfiguration.load( configFile);
		MailBridge.log( Level.INFO, "Configuration: " + config);

		// Create the decryptor from configuration
		Decryptor decryptor = config.createDecryptor();

		// Create the login handler from configuration
		LoginHandler loginHandler = config.createLoginHandler();

		List<Thread> listenerThreads = new ArrayList<>();

		// Start plain IMAP listener if enabled
		if( config.isPlainEnabled())
		{
			Thread plainListener = new Thread( () -> runPlainListener( config, decryptor, loginHandler), "IMAP-Listener");
			plainListener.start();
			listenerThreads.add( plainListener);
		}

		// Start IMAPS listener if enabled
		if( config.isImapsEnabled())
		{
			Thread imapsListener = new Thread( () -> runImapsListener( config, decryptor, loginHandler), "IMAPS-Listener");
			imapsListener.start();
			listenerThreads.add( imapsListener);
		}

		// Start SMTP submission proxy if enabled
		if( config.isSmtpEnabled())
		{
			Thread smtpListener = new Thread( () -> runSmtpListener( config, loginHandler), "SMTP-Listener");
			smtpListener.start();
			listenerThreads.add( smtpListener);
		}

		if( listenerThreads.isEmpty())
		{
			MailBridge.log( Level.ERROR, "No listeners enabled! Enable plainEnabled or imapsEnabled in configuration.");
			return;
		}

		// Wait for all listener threads
		for( Thread listener : listenerThreads)
		{
			try {
				listener.join();
			} catch( InterruptedException e) {
				MailBridge.log( Level.ERROR, "Listener interrupted", e);
			}
		}
	}

	/**
	 * Run the plain IMAP listener on the configured port.
	 */
	private static void runPlainListener( BridgeConfiguration config, Decryptor decryptor, LoginHandler loginHandler)
	{
		ServerSocket serverSocket = null;

		try {
			serverSocket = new ServerSocket( config.getListenPort());
			MailBridge.log( Level.INFO, "Started plain IMAP listener on port " + config.getListenPort());

			while( true)
			{
				Socket clientSocket = serverSocket.accept();
				clientSocket.setKeepAlive( true);
				MailBridge.log( Level.INFO, "Received plain IMAP connection from " + clientSocket.getRemoteSocketAddress());

				ProxyChannel proxyChannel = new ProxyChannel( clientSocket, config, decryptor, loginHandler);
				new Thread( proxyChannel).start();
			}
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, "Plain IMAP listener error: " + e.toString(), e);
		} finally {
			if( serverSocket != null)
			{
				try {
					serverSocket.close();
				} catch( IOException e) {
					MailBridge.log( Level.ERROR, "Error closing plain IMAP socket", e);
				}
			}
		}
	}

	/**
	 * Run the IMAPS (TLS) listener on the configured port.
	 */
	private static void runImapsListener( BridgeConfiguration config, Decryptor decryptor, LoginHandler loginHandler)
	{
		SSLServerSocket serverSocket = null;

		try {
			// Create SSL server socket factory from PEM files
			SSLServerSocketFactory sslFactory = PemSslContextFactory.createServerSocketFactory(
				config.getImapsCertPath(),
				config.getImapsKeyPath(),
				config.getTlsProtocol());

			serverSocket = (SSLServerSocket) sslFactory.createServerSocket( config.getImapsListenPort());
			MailBridge.log( Level.INFO, "Started IMAPS listener on port " + config.getImapsListenPort());

			while( true)
			{
				Socket clientSocket = serverSocket.accept();
				clientSocket.setKeepAlive( true);
				MailBridge.log( Level.INFO, "Received IMAPS connection from " + clientSocket.getRemoteSocketAddress());

				ProxyChannel proxyChannel = new ProxyChannel( clientSocket, config, decryptor, loginHandler);
				new Thread( proxyChannel).start();
			}
		} catch( Exception e) {
			MailBridge.log( Level.ERROR, "IMAPS listener error: " + e.toString(), e);
		} finally {
			if( serverSocket != null)
			{
				try {
					serverSocket.close();
				} catch( IOException e) {
					MailBridge.log( Level.ERROR, "Error closing IMAPS socket", e);
				}
			}
		}
	}
	
	/**
	 * Run the SMTP submission proxy listener on the configured port.
	 */
	private static void runSmtpListener( BridgeConfiguration config, LoginHandler loginHandler)
	{
		ServerSocket serverSocket = null;

		try {
			serverSocket = new ServerSocket( config.getSmtpListenPort());
			MailBridge.log( Level.INFO, "Started SMTP submission proxy on port " + config.getSmtpListenPort());

			while( true)
			{
				Socket clientSocket = serverSocket.accept();
				clientSocket.setKeepAlive( true);
				MailBridge.log( Level.INFO, "Received SMTP connection from " + clientSocket.getRemoteSocketAddress());

				SmtpProxyChannel proxyChannel = new SmtpProxyChannel( clientSocket, config, loginHandler);
				new Thread( proxyChannel).start();
			}
		} catch( IOException e) {
			MailBridge.log( Level.ERROR, "SMTP listener error: " + e.toString(), e);
		} finally {
			if( serverSocket != null)
			{
				try {
					serverSocket.close();
				} catch( IOException e) {
					MailBridge.log( Level.ERROR, "Error closing SMTP socket", e);
				}
			}
		}
	}

	public static void log( Level level, String message)
	{
		LOGGER.log( level, message);
	}

	public static void log( Level level, String message, Throwable thrown)
	{
		LOGGER.log( level, message, thrown);
	}

	public static void info( String message)
	{
		LOGGER.info( message);
	}

	public static void error( String message, Throwable thrown)
	{
		LOGGER.error( message, thrown);
	}

	public static void debug( String message)
	{
		LOGGER.debug( message);
	}

	public static void trace( String message)
	{
		LOGGER.trace( message);
	}
}
