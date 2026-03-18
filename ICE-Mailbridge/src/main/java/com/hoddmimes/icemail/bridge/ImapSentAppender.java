/**
 * Appends an encrypted copy of a sent mail to the user's Sent folder via IMAP.
 * Connects directly to the upstream IMAP server (Apache James) using TLS,
 * authenticating with the user's hashed password.
 *
 * Called by SmtpProxyChannel after successful SMTP delivery to ensure the
 * Sent folder always contains an encrypted copy, regardless of whether the
 * mail client attempts to save its own copy.
 */

package com.hoddmimes.icemail.bridge;

import org.apache.logging.log4j.Level;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class ImapSentAppender
{
	private static final String SENT_FOLDER = "Sent";

	/**
	 * Append an encrypted mail to the user's Sent folder.
	 *
	 * @param host             Upstream IMAP server hostname
	 * @param port             Upstream IMAP server port (TLS)
	 * @param sslFactory       SSLSocketFactory for the TLS connection
	 * @param username         Username for IMAP authentication
	 * @param hashedPassword   Hashed password (what James accepts)
	 * @param rawEncryptedMail Full MIME message with encrypted body
	 */
	public static void append( String host, int port, SSLSocketFactory sslFactory,
		String username, String hashedPassword, String rawEncryptedMail)
	{
		try
		{
			MailBridge.log( Level.INFO, "ImapSentAppender: appending to folder '" + SENT_FOLDER + "' for " + username);
			byte[] msgBytes = rawEncryptedMail.getBytes( StandardCharsets.UTF_8);

			Socket baseSocket = new Socket( host, port);
			SSLSocket sslSocket = (SSLSocket) sslFactory.createSocket( baseSocket, host, port, true);

			javax.net.ssl.SSLParameters params = sslSocket.getSSLParameters();
			params.setEndpointIdentificationAlgorithm( null);
			sslSocket.setSSLParameters( params);
			sslSocket.startHandshake();

			BufferedReader reader = new BufferedReader(
				new InputStreamReader( sslSocket.getInputStream(), StandardCharsets.UTF_8));
			OutputStream out = sslSocket.getOutputStream();

			// Read server greeting
			String greeting = reader.readLine();
			MailBridge.log( Level.DEBUG, "ImapSentAppender << " + greeting);

			// Authenticate
			send( out, "A001 LOGIN " + username + " " + hashedPassword);
			String loginResp = reader.readLine();
			MailBridge.log( Level.DEBUG, "ImapSentAppender << " + loginResp);
			if( loginResp == null || !loginResp.contains( "OK"))
			{
				MailBridge.log( Level.ERROR, "ImapSentAppender: IMAP login failed for " + username + ", folder '" + SENT_FOLDER + "': " + loginResp);
				sslSocket.close();
				return;
			}

			// Send APPEND with literal byte count
			send( out, "A002 APPEND " + SENT_FOLDER + " (\\Seen) {" + msgBytes.length + "}");
			String contResp = reader.readLine();
			MailBridge.log( Level.DEBUG, "ImapSentAppender << " + contResp);
			if( contResp == null || !contResp.startsWith( "+"))
			{
				MailBridge.log( Level.ERROR, "ImapSentAppender: no APPEND continuation for " + username + ", folder '" + SENT_FOLDER + "': " + contResp);
				sslSocket.close();
				return;
			}

			// Write the message literal followed by CRLF
			out.write( msgBytes);
			out.write( "\r\n".getBytes( StandardCharsets.UTF_8));
			out.flush();

			String appendResp = reader.readLine();
			MailBridge.log( Level.DEBUG, "ImapSentAppender << " + appendResp);
			if( appendResp == null || !appendResp.contains( "OK"))
			{
				MailBridge.log( Level.WARN, "ImapSentAppender: APPEND failed for " + username + ", folder '" + SENT_FOLDER + "': " + appendResp);
			}
			else
			{
				MailBridge.log( Level.INFO, "ImapSentAppender: APPEND OK, folder '" + SENT_FOLDER + "' for " + username);
			}

			// Clean logout
			send( out, "A003 LOGOUT");
			reader.readLine(); // * BYE
			reader.readLine(); // A003 OK

			sslSocket.close();
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "ImapSentAppender: failed to append sent copy for " + username, e);
		}
	}

	private static void send( OutputStream out, String cmd) throws IOException
	{
		MailBridge.log( Level.DEBUG, "ImapSentAppender >> " + cmd);
		out.write( (cmd + "\r\n").getBytes( StandardCharsets.UTF_8));
		out.flush();
	}
}
