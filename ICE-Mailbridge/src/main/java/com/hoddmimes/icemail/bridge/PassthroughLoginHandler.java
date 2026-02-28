/**
 * Default login handler that passes login requests through unchanged.
 */

package com.hoddmimes.icemail.bridge;

import org.apache.logging.log4j.Level;

public class PassthroughLoginHandler implements LoginHandler
{
	public PassthroughLoginHandler()
	{
		MailBridge.log( Level.INFO, "Using passthrough login handler - credentials will not be modified");
	}

	@Override
	public LoginResult executeLogin( String username, String password)
	{
		MailBridge.log( Level.DEBUG, "Passthrough login for user: " + username);
		return LoginResult.passthrough( username, password);
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
