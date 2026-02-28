/**
 * Configuration for the ICE Mailbridge.
 * Loaded from a JSON configuration file at startup.
 */

package com.hoddmimes.icemail.bridge;

import java.io.FileReader;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.logging.log4j.Level;

public class BridgeConfiguration
{
	private static final String DEFAULT_CONFIG_FILE = "mailbridge.json";

	// Client connection settings - plain IMAP
	private int listenPort = 143;
	private boolean plainEnabled = true;

	// Client connection settings - IMAPS (TLS)
	private int imapsListenPort = 993;
	private boolean imapsEnabled = false;
	private String imapsCertPath = "cert.pem";
	private String imapsKeyPath = "key.pem";

	// IMAP server connection settings
	private String imapHost = "localhost";
	private int imapPort = 993;

	// Decryptor implementation class name
	private String decryptorClass = "com.hoddmimes.icemail.bridge.PassthroughDecryptor";

	// Login handler implementation class name
	private String loginHandlerClass = "com.hoddmimes.icemail.bridge.PassthroughLoginHandler";

	// SMTP submission proxy settings
	private boolean smtpEnabled = false;
	private int smtpListenPort = 1587;
	private String smtpHost = "localhost";
	private int smtpPort = 587;

	// TLS protocol version
	private String tlsProtocol = "TLSv1.3";

	/**
	 * Load configuration from the default config file.
	 */
	public static BridgeConfiguration load()
	{
		return load( DEFAULT_CONFIG_FILE);
	}

	/**
	 * Load configuration from a specified file.
	 *
	 * @param configFile Path to the JSON configuration file
	 * @return Configuration object, or default configuration if file not found
	 */
	public static BridgeConfiguration load( String configFile)
	{
		try( FileReader reader = new FileReader( configFile))
		{
			Gson gson = new Gson();
			BridgeConfiguration config = gson.fromJson( reader, BridgeConfiguration.class);
			MailBridge.log( Level.INFO, "Loaded configuration from " + configFile);
			return config;
		}
		catch( IOException e)
		{
			MailBridge.log( Level.WARN, "Could not load config file " + configFile + ", using defaults: " + e.getMessage());
			return new BridgeConfiguration();
		}
	}

	/**
	 * Create a Decryptor instance based on the configured class name.
	 *
	 * @return Decryptor instance, or PassthroughDecryptor if instantiation fails
	 */
	public Decryptor createDecryptor()
	{
		try
		{
			Class<?> clazz = Class.forName( decryptorClass);
			if( !Decryptor.class.isAssignableFrom( clazz))
			{
				MailBridge.log( Level.ERROR, "Class " + decryptorClass + " does not implement Decryptor interface");
				return new PassthroughDecryptor();
			}

			Decryptor decryptor = (Decryptor) clazz.getDeclaredConstructor().newInstance();
			MailBridge.log( Level.INFO, "Created decryptor instance: " + decryptorClass);
			return decryptor;
		}
		catch( ClassNotFoundException e)
		{
			MailBridge.log( Level.ERROR, "Decryptor class not found: " + decryptorClass, e);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "Failed to instantiate decryptor: " + decryptorClass, e);
		}

		MailBridge.log( Level.WARN, "Falling back to PassthroughDecryptor");
		return new PassthroughDecryptor();
	}

	/**
	 * Create a LoginHandler instance based on the configured class name.
	 *
	 * @return LoginHandler instance, or PassthroughLoginHandler if instantiation fails
	 */
	public LoginHandler createLoginHandler()
	{
		try
		{
			Class<?> clazz = Class.forName( loginHandlerClass);
			if( !LoginHandler.class.isAssignableFrom( clazz))
			{
				MailBridge.log( Level.ERROR, "Class " + loginHandlerClass + " does not implement LoginHandler interface");
				return new PassthroughLoginHandler();
			}

			LoginHandler handler = (LoginHandler) clazz.getDeclaredConstructor().newInstance();
			MailBridge.log( Level.INFO, "Created login handler instance: " + loginHandlerClass);
			return handler;
		}
		catch( ClassNotFoundException e)
		{
			MailBridge.log( Level.ERROR, "LoginHandler class not found: " + loginHandlerClass, e);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "Failed to instantiate login handler: " + loginHandlerClass, e);
		}

		MailBridge.log( Level.WARN, "Falling back to PassthroughLoginHandler");
		return new PassthroughLoginHandler();
	}

	/**
	 * Save the current configuration to a file (useful for generating default config).
	 *
	 * @param configFile Path to write the configuration
	 */
	public void save( String configFile) throws IOException
	{
		try( java.io.FileWriter writer = new java.io.FileWriter( configFile))
		{
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			gson.toJson( this, writer);
		}
	}

	// Getters

	public int getListenPort()
	{
		return listenPort;
	}

	public boolean isPlainEnabled()
	{
		return plainEnabled;
	}

	public int getImapsListenPort()
	{
		return imapsListenPort;
	}

	public boolean isImapsEnabled()
	{
		return imapsEnabled;
	}

	public String getImapsCertPath()
	{
		return imapsCertPath;
	}

	public String getImapsKeyPath()
	{
		return imapsKeyPath;
	}

	public String getImapHost()
	{
		return imapHost;
	}

	public int getImapPort()
	{
		return imapPort;
	}

	public String getDecryptorClass()
	{
		return decryptorClass;
	}

	public String getLoginHandlerClass()
	{
		return loginHandlerClass;
	}

	public boolean isSmtpEnabled()
	{
		return smtpEnabled;
	}

	public int getSmtpListenPort()
	{
		return smtpListenPort;
	}

	public String getSmtpHost()
	{
		return smtpHost;
	}

	public int getSmtpPort()
	{
		return smtpPort;
	}

	public String getTlsProtocol()
	{
		return tlsProtocol;
	}

	// Setters (for programmatic configuration)

	public void setListenPort( int listenPort)
	{
		this.listenPort = listenPort;
	}

	public void setPlainEnabled( boolean plainEnabled)
	{
		this.plainEnabled = plainEnabled;
	}

	public void setImapsListenPort( int imapsListenPort)
	{
		this.imapsListenPort = imapsListenPort;
	}

	public void setImapsEnabled( boolean imapsEnabled)
	{
		this.imapsEnabled = imapsEnabled;
	}

	public void setImapsCertPath( String imapsCertPath)
	{
		this.imapsCertPath = imapsCertPath;
	}

	public void setImapsKeyPath( String imapsKeyPath)
	{
		this.imapsKeyPath = imapsKeyPath;
	}

	public void setImapHost( String imapHost)
	{
		this.imapHost = imapHost;
	}

	public void setImapPort( int imapPort)
	{
		this.imapPort = imapPort;
	}

	public void setDecryptorClass( String decryptorClass)
	{
		this.decryptorClass = decryptorClass;
	}

	public void setLoginHandlerClass( String loginHandlerClass)
	{
		this.loginHandlerClass = loginHandlerClass;
	}

	public void setSmtpEnabled( boolean smtpEnabled)
	{
		this.smtpEnabled = smtpEnabled;
	}

	public void setSmtpListenPort( int smtpListenPort)
	{
		this.smtpListenPort = smtpListenPort;
	}

	public void setSmtpHost( String smtpHost)
	{
		this.smtpHost = smtpHost;
	}

	public void setSmtpPort( int smtpPort)
	{
		this.smtpPort = smtpPort;
	}

	public void setTlsProtocol( String tlsProtocol)
	{
		this.tlsProtocol = tlsProtocol;
	}

	@Override
	public String toString()
	{
		return "BridgeConfiguration{" +
			"listenPort=" + listenPort +
			", plainEnabled=" + plainEnabled +
			", imapsListenPort=" + imapsListenPort +
			", imapsEnabled=" + imapsEnabled +
			", imapsCertPath='" + imapsCertPath + '\'' +
			", imapsKeyPath='" + imapsKeyPath + '\'' +
			", imapHost='" + imapHost + '\'' +
			", imapPort=" + imapPort +
			", decryptorClass='" + decryptorClass + '\'' +
			", loginHandlerClass='" + loginHandlerClass + '\'' +
			", smtpEnabled=" + smtpEnabled +
			", smtpListenPort=" + smtpListenPort +
			", smtpHost='" + smtpHost + '\'' +
			", smtpPort=" + smtpPort +
			", tlsProtocol='" + tlsProtocol + '\'' +
			'}';
	}
}
