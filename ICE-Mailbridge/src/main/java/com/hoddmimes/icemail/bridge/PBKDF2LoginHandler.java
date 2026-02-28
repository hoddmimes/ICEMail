/**
 * Default login handler that passes login requests through unchanged.
 */

package com.hoddmimes.icemail.bridge;

import org.apache.logging.log4j.Level;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;

public class PBKDF2LoginHandler implements LoginHandler
{




	public PBKDF2LoginHandler()
	{
		MailBridge.log( Level.INFO, "Login passwords i cleartext will be hashed using the algorithm PBKDF2");
	}

	@Override
	public LoginResult executeLogin( String username, String password)
	{
		MailBridge.log( Level.DEBUG, "PBKDF2 login for user: " + username);
		try {
			String tHashedPassword = PBKDF2Hash.hash(username, password);
			System.out.println("username: " + username + " password: " + password + " hashed password: " + tHashedPassword);
			MailBridge.log( Level.DEBUG, "PBKDF2 user password successfully hashed");
			return LoginResult.modified(username, tHashedPassword);
		}
		catch( Exception e) {
			MailBridge.log( Level.ERROR, "fail to hash password with PBKDF2", e);
			return LoginResult.passthrough(username, password);
		}
	}

	@Override
	public boolean isReady()
	{
		return true;
	}

	@Override
	public void initialize( String config)
	{
		// No-op for passthrough implementation
		MailBridge.log( Level.DEBUG, "PassthroughLoginHandler.initialize called - ignoring config");
	}
}
