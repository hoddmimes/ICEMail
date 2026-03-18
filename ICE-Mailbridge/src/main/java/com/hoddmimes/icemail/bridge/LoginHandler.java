/**
 * Interface for handling IMAP login requests.
 * Allows custom authentication logic to be injected at startup.
 */

package com.hoddmimes.icemail.bridge;

public interface LoginHandler
{
	/**
	 * Execute login processing when a mail client attempts to log in to the IMAP server.
	 *
	 * @param username The username from the LOGIN command
	 * @param password The password from the LOGIN command
	 * @return LoginResult containing potentially modified credentials or the original ones
	 */
	LoginResult executeLogin( String username, String password);

	/**
	 * Check if the handler is ready to process logins.
	 *
	 * @return true if the handler is configured and ready
	 */
	boolean isReady();

	/**
	 * Initialize the handler with any required configuration.
	 * Called once at startup.
	 *
	 * @param config Configuration parameters (implementation-specific)
	 */
	void initialize( String config);

	/**
	 * Result of login processing.
	 */
	class LoginResult
	{
		private final String username;
		private final String password;
		private final boolean modified;
		private final boolean blocked;
		private final String blockReason;

		/**
		 * The user's encrypted private key returned by the ICEMail server on successful login.
		 * Base64-encoded PGP-symmetric-encrypted armored PGP private key.
		 * Null if the server did not return one (e.g. passthrough handler).
		 */
		private final String encryptedPrivateKey;

		/**
		 * The user's armored PGP public key returned by the ICEMail server on successful login.
		 * Used to encrypt the Sent copy without loading the secret key ring.
		 * Null if the server did not return one (e.g. passthrough handler).
		 */
		private final String publicKey;

		/**
		 * Create a pass-through result (unchanged credentials).
		 */
		public static LoginResult passthrough( String username, String password)
		{
			return new LoginResult( username, password, false, false, null, null, null);
		}

		/**
		 * Create a modified result with new credentials.
		 */
		public static LoginResult modified( String newUsername, String newPassword)
		{
			return new LoginResult( newUsername, newPassword, true, false, null, null, null);
		}

		/**
		 * Create a modified result with new credentials, encrypted private key and public key.
		 */
		public static LoginResult modified( String newUsername, String newPassword, String encryptedPrivateKey, String publicKey)
		{
			return new LoginResult( newUsername, newPassword, true, false, null, encryptedPrivateKey, publicKey);
		}

		/**
		 * Create a blocked result (login should be rejected).
		 */
		public static LoginResult blocked( String reason)
		{
			return new LoginResult( null, null, false, true, reason, null, null);
		}

		private LoginResult( String username, String password, boolean modified, boolean blocked, String blockReason, String encryptedPrivateKey, String publicKey)
		{
			this.username = username;
			this.password = password;
			this.modified = modified;
			this.blocked = blocked;
			this.blockReason = blockReason;
			this.encryptedPrivateKey = encryptedPrivateKey;
			this.publicKey = publicKey;
		}

		public String getUsername()
		{
			return username;
		}

		public String getPassword()
		{
			return password;
		}

		public boolean isModified()
		{
			return modified;
		}

		public boolean isBlocked()
		{
			return blocked;
		}

		public String getBlockReason()
		{
			return blockReason;
		}

		public String getEncryptedPrivateKey()
		{
			return encryptedPrivateKey;
		}

		public String getPublicKey()
		{
			return publicKey;
		}

		/**
		 * Reconstruct the IMAP LOGIN command with the (possibly modified) credentials.
		 *
		 * @param tag The IMAP command tag (e.g., "A001")
		 * @return The full LOGIN command string
		 */
		public String toImapCommand( String tag)
		{
			return tag + " LOGIN " + username + " " + password;
		}
	}
}
