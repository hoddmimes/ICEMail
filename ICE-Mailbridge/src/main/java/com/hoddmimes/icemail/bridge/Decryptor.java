/**
 * Interface for mail decryption implementations.
 * Allows different decryption strategies to be loaded at startup.
 */

package com.hoddmimes.icemail.bridge;

public interface Decryptor
{
	/**
	 * Decrypt the subject within an IMAP ENVELOPE response.
	 *
	 * @param envelopeLine Line containing ENVELOPE data
	 * @return Line with decrypted subject (or unchanged if not encrypted/decryption disabled)
	 */
	String decryptSubjectInEnvelope( String envelopeLine);

	/**
	 * Decrypt the subject in a raw email header line.
	 *
	 * @param headerLine Line containing "Subject: ..."
	 * @return Line with decrypted subject (or unchanged if not encrypted/decryption disabled)
	 */
	String decryptSubjectInHeader( String headerLine);

	/**
	 * Decrypt the email body content.
	 *
	 * @param content Full email content that may contain encrypted body
	 * @return Content with decrypted body (or unchanged if not encrypted/decryption disabled)
	 */
	String decryptBody( String content);

	/**
	 * Check if the decryptor is configured and ready to decrypt.
	 *
	 * @return true if decryption is enabled and configured
	 */
	boolean isReady();

	/**
	 * Configure the decryptor with credentials/keys.
	 * Implementation-specific; may be a no-op for passthrough decryptors.
	 *
	 * @param privateKey The private key (format depends on implementation)
	 * @param passphrase Passphrase to unlock the private key
	 */
	void initialize( String privateKey, String passphrase);
}
