/**
 * Login handler that authenticates against the ICEMail server REST API.
 * Hashes the user password with PBKDF2 and posts it to /api/bridge/login.
 * On success the server returns the user's encrypted private key which is
 * carried back in the LoginResult so ProxyChannel can hand it to the Decryptor.
 */

package com.hoddmimes.icemail.bridge;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.logging.log4j.Level;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class BridgeServerLoginHandler implements LoginHandler
{
	private String serverBaseUrl = "https://localhost:8282";

	public BridgeServerLoginHandler()
	{
	}

	@Override
	public void initialize( String config)
	{
		if( config != null && !config.isEmpty())
		{
			serverBaseUrl = config.trim();
		}
		MailBridge.log( Level.INFO, "BridgeServerLoginHandler configured with server: " + serverBaseUrl);
	}

	@Override
	public boolean isReady()
	{
		return true;
	}

	@Override
	public LoginResult executeLogin( String username, String password)
	{
		MailBridge.log( Level.DEBUG, "BridgeServerLoginHandler: login for user: " + username);

		String hashedPassword;
		try
		{
			hashedPassword = PBKDF2Hash.hash( username, password);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "Failed to hash password for user: " + username, e);
			return LoginResult.blocked( "Internal error during authentication");
		}

		try
		{
			JsonObject body = new JsonObject();
			body.addProperty( "username", username);
			body.addProperty( "password", hashedPassword);

			String loginUrl = serverBaseUrl + "/login";
			MailBridge.log( Level.INFO, "Connecting to ICEMail service at " + loginUrl + " for user: " + username);
			String responseJson = httpPost( loginUrl, body.toString());
			if( responseJson == null)
			{
				MailBridge.log( Level.ERROR, "No response from ICEMail server for user: " + username);
				return LoginResult.blocked( "Authentication server unreachable");
			}

			JsonObject jResponse = JsonParser.parseString( responseJson).getAsJsonObject();

			if( jResponse.has( "status") && jResponse.get( "status").getAsInt() != 200)
			{
				String message = jResponse.has( "message") ? jResponse.get( "message").getAsString() : "Authentication failed";
				MailBridge.log( Level.WARN, "Bridge login rejected for user " + username + ": " + message);
				return LoginResult.blocked( message);
			}

			String encryptedPrivateKey = jResponse.has( "privateKey") ? jResponse.get( "privateKey").getAsString() : null;
			String publicKey = jResponse.has( "publicKey") ? jResponse.get( "publicKey").getAsString() : null;
			MailBridge.log( Level.INFO, "BridgeServerLoginHandler: login successful for user: " + username);
			return LoginResult.modified( username, hashedPassword, encryptedPrivateKey, publicKey);
		}
		catch( java.io.IOException e)
		{
			String msg = e.getMessage();
			if( msg != null && msg.startsWith( "HTTP 4"))
			{
				MailBridge.log( Level.WARN, "Bridge login rejected for user " + username + ": " + msg);
				return LoginResult.blocked( "Authentication failed");
			}
			MailBridge.log( Level.ERROR, "Bridge login API call failed for user: " + username, e);
			return LoginResult.blocked( "Authentication server error");
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "Bridge login API call failed for user: " + username, e);
			return LoginResult.blocked( "Authentication server error");
		}
	}

	/**
	 * POST a JSON body to the given URL and return the response body as a String.
	 * Accepts self-signed certificates (the ICEMail server may use one).
	 */
	private String httpPost( String urlStr, String jsonBody) throws Exception
	{
		URL url = new URI( urlStr).toURL();
		HttpURLConnection conn;

		MailBridge.log( Level.DEBUG, "Opening HTTP connection to " + urlStr);
		if( urlStr.startsWith( "https"))
		{
			SSLContext sslContext = SSLContext.getInstance( "TLS");
			sslContext.init( null, new X509TrustManager[]{ new CustomTrustManager()}, new SecureRandom());

			HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
			httpsConn.setSSLSocketFactory( sslContext.getSocketFactory());
			httpsConn.setHostnameVerifier( (hostname, session) -> true);
			conn = httpsConn;
		}
		else
		{
			conn = (HttpURLConnection) url.openConnection();
		}

		conn.setRequestMethod( "POST");
		conn.setRequestProperty( "Content-Type", "application/json");
		conn.setRequestProperty( "Accept", "application/json");
		conn.setConnectTimeout( 5000);
		conn.setReadTimeout( 10000);
		conn.setDoOutput( true);

		try( OutputStream os = conn.getOutputStream())
		{
			os.write( jsonBody.getBytes( StandardCharsets.UTF_8));
		}

		int status = conn.getResponseCode();
		MailBridge.log( Level.INFO, "ICEMail service responded with HTTP " + status + " from " + urlStr);

		if( status < 200 || status >= 300)
		{
			throw new java.io.IOException( "HTTP " + status);
		}

		java.io.InputStream is = conn.getInputStream();
		if( is == null)
		{
			return null;
		}

		StringBuilder sb = new StringBuilder();
		try( BufferedReader reader = new BufferedReader( new InputStreamReader( is, StandardCharsets.UTF_8)))
		{
			String line;
			while( (line = reader.readLine()) != null)
			{
				sb.append( line);
			}
		}

		return sb.toString();
	}
}
