/**
 * Default decryptor implementation that passes all messages through unchanged.
 * Use this when decryption is not needed or not yet configured.
 */

package com.hoddmimes.icemail.bridge;

import org.apache.logging.log4j.Level;

public class PassthroughDecryptor implements Decryptor
{
	public PassthroughDecryptor()
	{
		MailBridge.log( Level.INFO, "Using passthrough decryptor - messages will not be decrypted");
	}

	@Override
	public String decryptSubjectInEnvelope( String envelopeLine)
	{
		return envelopeLine;
	}

	@Override
	public String decryptSubjectInHeader( String headerLine)
	{
		return headerLine;
	}

	@Override
	public String decryptBody( String content)
	{
		return content;
	}

	@Override
	public boolean isReady()
	{
		return false;
	}

	@Override
	public void initialize( String privateKey, String passphrase)
	{
		// No-op for passthrough implementation
		MailBridge.log( Level.DEBUG, "PassthroughDecryptor.initialize called - ignoring");
	}
}
