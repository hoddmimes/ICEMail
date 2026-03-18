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
	 * Initialize the decryptor for a user session.
	 * Called at login time with the encrypted private key and public key returned by the ICEMail server
	 * and the user's plaintext password needed to unlock the private key.
	 *
	 * @param encryptedPrivateKey Base64-encoded PGP-symmetric-encrypted armored PGP private key
	 * @param plaintextPassword   The user's plaintext password (used both to decrypt the key wrapper
	 *                            and as the PGP key passphrase)
	 * @param publicKey           Armored PGP public key (used to encrypt the Sent copy)
	 */
	void initialize( String encryptedPrivateKey, String plaintextPassword, String publicKey);
}
