/**
 * Encrypts an outgoing SMTP mail when the Subject header contains the trigger prefix
 * "encrypt:<password>:<actual subject>" (case-insensitive, optional Re:/Fwd: prefix).
 *
 * The encryption matches the compose-page format exactly:
 *   AES-256-GCM with PBKDF2(SHA-256, 100 000 iterations), 16-byte salt, 12-byte IV.
 *   Payload: base64( JSON{ salt, iv, ciphertext } )
 *   Wrapped:  -----BEGIN ICE ENCRYPTED MESSAGE-----
 *             <base64payload>
 *             -----END ICE ENCRYPTED MESSAGE-----
 *
 * The X-ICE-UID header is added so the PostfixAfterQueueFilter treats the mail
 * identically to one sent from the compose web page.
 */

package com.hoddmimes.icemail.bridge;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.Level;

public class SmtpMailEncryptor
{
	private static final int MIN_PASSWORD_LENGTH = 8;
	private static final int PBKDF2_ITERATIONS   = 100_000;
	private static final int SALT_BYTES           = 16;
	private static final int IV_BYTES             = 12;
	private static final int GCM_TAG_BITS         = 128;

	private static final String ICE_BEGIN = "-----BEGIN ICE ENCRYPTED MESSAGE-----";
	private static final String ICE_END   = "-----END ICE ENCRYPTED MESSAGE-----";

	// Optional Re:/Fwd:/Fw: prefix, then "encrypt:<password>:<rest of subject>"
	// Password must not contain ':'; rest of subject can contain anything.
	private static final Pattern SUBJECT_PATTERN = Pattern.compile(
		"^((?:Re|Fwd|Fw)\\s*:\\s*)?encrypt:([^:]+):(.*)$",
		Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

	// Matches "boundary=..." parameter in Content-Type (quoted or unquoted)
	private static final Pattern BOUNDARY_PATTERN = Pattern.compile(
		"boundary\\s*=\\s*(?:\"([^\"]+)\"|([^;\\s]+))",
		Pattern.CASE_INSENSITIVE);

	// MIME encoded-word: =?charset?B|Q?encoded?=
	private static final Pattern ENCODED_WORD_PATTERN = Pattern.compile(
		"=\\?([^?]+)\\?([BQbq])\\?([^?]*)\\?=");

	/**
	 * Process a raw email (headers + body as a single string with CRLF line endings).
	 * Returns the modified mail if the Subject triggered encryption, otherwise null.
	 */
	public static String process( String rawMail)
	{
		// Split headers and body on first blank line
		int sepIdx = rawMail.indexOf( "\r\n\r\n");
		String sep = "\r\n\r\n";
		if( sepIdx < 0) { sepIdx = rawMail.indexOf( "\n\n"); sep = "\n\n"; }
		if( sepIdx < 0) return null;

		String headers = rawMail.substring( 0, sepIdx);
		String body    = rawMail.substring( sepIdx + sep.length());

		String subject = extractHeaderValue( headers, "Subject");
		if( subject == null) return null;

		// Mail clients encode subjects containing non-ASCII characters using MIME
		// encoded-words (e.g. =?utf-8?Q?Encrypt:pw:subject?=).  Decode before matching.
		subject = decodeMimeEncodedWords( subject);

		Matcher m = SUBJECT_PATTERN.matcher( subject.trim());
		if( !m.matches()) return null;

		String rePrefix    = m.group(1) != null ? m.group(1).trim() + " " : "";
		String password    = m.group(2).trim();
		String restSubject = m.group(3);
		String actualSubject = rePrefix + restSubject;

		if( password.length() < MIN_PASSWORD_LENGTH)
		{
			MailBridge.log( Level.WARN, "SmtpMailEncryptor: password too short (< "
				+ MIN_PASSWORD_LENGTH + " chars), not encrypting");
			return null;
		}

		MailBridge.log( Level.INFO, "SmtpMailEncryptor: encrypting outgoing mail, subject='"
			+ actualSubject + "'");

		try {
			// Extract human-readable text from the MIME body
			String contentType = extractHeaderValue( headers, "Content-Type");
			String cte         = extractHeaderValue( headers, "Content-Transfer-Encoding");
			String plaintext   = extractText( body, contentType, cte);

			// Generate X-ICE-UID (16 random bytes → 32 hex chars)
			byte[] uidBytes = new byte[16];
			new SecureRandom().nextBytes( uidBytes);
			String iceUid = bytesToHex( uidBytes);

			// Encrypt and wrap
			String encPayload  = aesGcmEncrypt( plaintext, password);
			String wrappedBody = ICE_BEGIN + "\n" + encPayload + "\n" + ICE_END;

			// Rebuild headers with corrected Subject, stripped MIME headers, added X-ICE-UID
			String newHeaders = rewriteHeaders( headers, actualSubject, iceUid);

			return newHeaders + "\r\n" + wrappedBody + "\r\n";

		} catch( Exception e) {
			MailBridge.log( Level.ERROR, "SmtpMailEncryptor: encryption failed", e);
			return null;
		}
	}

	// -------------------------------------------------------------------------
	// Header utilities
	// -------------------------------------------------------------------------

	/**
	 * Extract the value of a named header (case-insensitive), handling folded headers.
	 */
	static String extractHeaderValue( String headers, String name)
	{
		String[] lines = headers.split( "\r?\n", -1);
		String prefix = name.toLowerCase() + ":";
		boolean found = false;
		StringBuilder val = new StringBuilder();

		for( String line : lines)
		{
			if( found)
			{
				if( line.startsWith( " ") || line.startsWith( "\t"))
					val.append( " ").append( line.trim());
				else
					break;
			}
			else if( line.toLowerCase().startsWith( prefix))
			{
				val.append( line.substring( prefix.length()).trim());
				found = true;
			}
		}
		return found ? val.toString() : null;
	}

	/**
	 * Rebuild the header block:
	 *  - replace Subject with the actual subject (encrypt prefix removed)
	 *  - remove Content-Type, Content-Transfer-Encoding, MIME-Version (we set new ones)
	 *  - add X-ICE-UID, new Content-Type, MIME-Version
	 */
	private static String rewriteHeaders( String originalHeaders, String newSubject, String iceUid)
	{
		StringBuilder sb = new StringBuilder();
		String[] lines = originalHeaders.split( "\r?\n", -1);
		boolean skipping = false;

		for( String line : lines)
		{
			if( skipping)
			{
				// Skip continuation lines of the header being removed
				if( line.startsWith( " ") || line.startsWith( "\t")) continue;
				skipping = false;
			}

			String lower = line.toLowerCase();
			if( lower.startsWith( "subject:"))
			{
				sb.append( "Subject: ").append( mimeEncodeIfNeeded( newSubject)).append( "\r\n");
			}
			else if( lower.startsWith( "content-type:")
				|| lower.startsWith( "content-transfer-encoding:")
				|| lower.startsWith( "mime-version:"))
			{
				skipping = true; // drop this header and its folded continuations
			}
			else if( !line.isEmpty())
			{
				sb.append( line).append( "\r\n");
			}
		}

		sb.append( "MIME-Version: 1.0\r\n");
		sb.append( "Content-Type: text/plain; charset=utf-8\r\n");
		sb.append( "X-ICE-UID: ").append( iceUid).append( "\r\n");
		return sb.toString();
	}

	// -------------------------------------------------------------------------
	// MIME body extraction
	// -------------------------------------------------------------------------

	/**
	 * Extract the human-readable text body from a raw MIME body.
	 * Handles text/plain, multipart (finds text/plain part), and
	 * Content-Transfer-Encoding: base64 / quoted-printable.
	 */
	private static String extractText( String body, String contentType, String cte)
	{
		if( contentType != null && contentType.toLowerCase().startsWith( "multipart/"))
		{
			Matcher bm = BOUNDARY_PATTERN.matcher( contentType);
			if( bm.find())
			{
				String boundary = bm.group(1) != null ? bm.group(1) : bm.group(2);
				String text = extractTextFromMultipart( body, boundary);
				if( text != null) return text;
			}
		}
		String charset = extractCharset( contentType);
		return decodeBody( body, cte, charset);
	}

	private static String extractTextFromMultipart( String body, String boundary)
	{
		String delim = "--" + boundary;
		String[] parts = body.split( Pattern.quote( delim), -1);

		for( String part : parts)
		{
			// Skip preamble, epilogue, and closing delimiter
			if( part.startsWith( "--") || part.trim().isEmpty()) continue;

			// Strip leading CRLF after boundary marker
			String p = part;
			if( p.startsWith( "\r\n")) p = p.substring( 2);
			else if( p.startsWith( "\n")) p = p.substring( 1);

			// Split part into its own headers and body
			int pSep = p.indexOf( "\r\n\r\n");
			String pSepStr = "\r\n\r\n";
			if( pSep < 0) { pSep = p.indexOf( "\n\n"); pSepStr = "\n\n"; }
			if( pSep < 0) continue;

			String partHeaders = p.substring( 0, pSep);
			String partBody    = p.substring( pSep + pSepStr.length());

			// Strip trailing CRLF that belongs to the next boundary line
			while( partBody.endsWith( "\r\n")) partBody = partBody.substring( 0, partBody.length() - 2);
			while( partBody.endsWith( "\n"))  partBody = partBody.substring( 0, partBody.length() - 1);

			String partCT  = extractHeaderValue( partHeaders, "Content-Type");
			String partCTE = extractHeaderValue( partHeaders, "Content-Transfer-Encoding");

			if( partCT == null || partCT.toLowerCase().startsWith( "text/plain"))
			{
				String charset = extractCharset( partCT);
				return decodeBody( partBody, partCTE, charset);
			}
		}
		return null;
	}

	/** Extract charset from a Content-Type header value, defaulting to UTF-8. */
	private static String extractCharset( String contentType)
	{
		if( contentType == null) return "utf-8";
		Pattern p = Pattern.compile( "charset\\s*=\\s*(?:\"([^\"]+)\"|([^;\\s]+))",
			Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher( contentType);
		if( m.find()) return m.group(1) != null ? m.group(1) : m.group(2);
		return "utf-8";
	}

	private static String decodeBody( String body, String cte, String charset)
	{
		if( cte == null
			|| cte.equalsIgnoreCase( "7bit")
			|| cte.equalsIgnoreCase( "8bit")
			|| cte.equalsIgnoreCase( "binary"))
		{
			// The SMTP stream is read as ISO-8859-1 (byte value = char value).
			// Recover the raw bytes and re-decode with the charset declared in Content-Type.
			try {
				String effectiveCharset = (charset != null && !charset.isBlank()) ? charset : "utf-8";
				return new String( body.getBytes( StandardCharsets.ISO_8859_1), effectiveCharset).trim();
			} catch( Exception e) {
				MailBridge.log( Level.WARN, "SmtpMailEncryptor: charset re-decode failed, using raw body", e);
				return body.trim();
			}
		}
		try {
			if( cte.equalsIgnoreCase( "base64"))
			{
				String b64 = body.replaceAll( "\\s+", "");
				return new String( Base64.getDecoder().decode( b64), charset).trim();
			}
			if( cte.equalsIgnoreCase( "quoted-printable"))
			{
				return decodeQuotedPrintable( body, charset).trim();
			}
		} catch( Exception e) {
			MailBridge.log( Level.WARN, "SmtpMailEncryptor: body decode failed, using raw body", e);
		}
		return body.trim();
	}

	/**
	 * Decode a quoted-printable body, collecting raw bytes and decoding with
	 * the specified charset. Treating each decoded byte as a char (the old approach)
	 * produces mojibake for multi-byte charsets like UTF-8.
	 */
	private static String decodeQuotedPrintable( String input, String charset) throws Exception
	{
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream( input.length());
		int i = 0;
		while( i < input.length())
		{
			char c = input.charAt( i);
			if( c == '=')
			{
				if( i + 1 < input.length()
					&& (input.charAt( i + 1) == '\r' || input.charAt( i + 1) == '\n'))
				{
					// Soft line break — skip
					i++;
					if( i < input.length() && input.charAt( i) == '\r') i++;
					if( i < input.length() && input.charAt( i) == '\n') i++;
				}
				else if( i + 2 < input.length())
				{
					try {
						baos.write( Integer.parseInt( input.substring( i + 1, i + 3), 16));
						i += 3;
					} catch( NumberFormatException e) {
						baos.write( (byte) c);
						i++;
					}
				}
				else { baos.write( (byte) c); i++; }
			}
			else
			{
				// ASCII printable — write the raw byte
				baos.write( (byte) c);
				i++;
			}
		}
		return baos.toString( charset);
	}

	// -------------------------------------------------------------------------
	// MIME encoded-word decoding (RFC 2047)
	// -------------------------------------------------------------------------

	/**
	 * Decode all MIME encoded-words in a header value.
	 * Handles both Base64 (B) and Quoted-Printable (Q) encodings.
	 * Example: "=?utf-8?Q?Encrypt:pw:Hello_fr=C3=A5n?=" → "Encrypt:pw:Hello från"
	 */
	private static String decodeMimeEncodedWords( String value)
	{
		if( value == null || !value.contains( "=?")) return value;

		Matcher m = ENCODED_WORD_PATTERN.matcher( value);
		StringBuffer sb = new StringBuffer();
		while( m.find())
		{
			String charset  = m.group(1);
			String encoding = m.group(2).toUpperCase();
			String encoded  = m.group(3);
			String decoded;
			try {
				if( encoding.equals( "B"))
				{
					byte[] bytes = Base64.getDecoder().decode( encoded);
					decoded = new String( bytes, charset);
				}
				else // Q encoding
				{
					decoded = decodeQEncoding( encoded, charset);
				}
			} catch( Exception e) {
				decoded = m.group(0); // leave unchanged on error
			}
			m.appendReplacement( sb, Matcher.quoteReplacement( decoded));
		}
		m.appendTail( sb);
		return sb.toString();
	}

	/**
	 * Decode a Q-encoded string (RFC 2047 section 4.2).
	 * '_' is decoded as space; '=XX' is decoded as the hex byte.
	 */
	private static String decodeQEncoding( String encoded, String charset) throws Exception
	{
		byte[] buf = new byte[encoded.length()];
		int len = 0;
		int i = 0;
		while( i < encoded.length())
		{
			char c = encoded.charAt( i);
			if( c == '_')
			{
				buf[len++] = 0x20;
				i++;
			}
			else if( c == '=' && i + 2 < encoded.length())
			{
				buf[len++] = (byte) Integer.parseInt( encoded.substring( i + 1, i + 3), 16);
				i += 3;
			}
			else
			{
				buf[len++] = (byte) c;
				i++;
			}
		}
		return new String( buf, 0, len, charset);
	}

	// -------------------------------------------------------------------------
	// AES-256-GCM encryption (matches webmail.js encryptBody())
	// -------------------------------------------------------------------------

	private static String aesGcmEncrypt( String plaintext, String password) throws Exception
	{
		SecureRandom rng  = new SecureRandom();
		byte[] salt = new byte[SALT_BYTES];
		byte[] iv   = new byte[IV_BYTES];
		rng.nextBytes( salt);
		rng.nextBytes( iv);

		// PBKDF2 key derivation (matches JS: SHA-256, 100 000 iterations, 256-bit)
		SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA256");
		SecretKey tmp = skf.generateSecret( new PBEKeySpec( password.toCharArray(), salt, PBKDF2_ITERATIONS, 256));
		SecretKey key = new SecretKeySpec( tmp.getEncoded(), "AES");

		// AES-GCM encryption (128-bit auth tag, matches JS default)
		Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding");
		cipher.init( Cipher.ENCRYPT_MODE, key, new GCMParameterSpec( GCM_TAG_BITS, iv));
		byte[] ciphertext = cipher.doFinal( plaintext.getBytes( StandardCharsets.UTF_8));

		// Build JSON payload exactly as webmail.js does, then base64-encode it
		String json = "{\"salt\":\""       + Base64.getEncoder().encodeToString( salt)
		            + "\",\"iv\":\""       + Base64.getEncoder().encodeToString( iv)
		            + "\",\"ciphertext\":\"" + Base64.getEncoder().encodeToString( ciphertext)
		            + "\"}";

		return Base64.getEncoder().encodeToString( json.getBytes( StandardCharsets.UTF_8));
	}

	private static String bytesToHex( byte[] bytes)
	{
		StringBuilder sb = new StringBuilder( bytes.length * 2);
		for( byte b : bytes)
			sb.append( String.format( "%02x", b));
		return sb.toString();
	}

	// -------------------------------------------------------------------------
	// MIME encoded-word encoding (RFC 2047)
	// -------------------------------------------------------------------------

	/**
	 * If the string contains non-ASCII characters, encode it as a MIME encoded-word
	 * using Base64 / UTF-8 ("=?utf-8?B?...?=").  Pure ASCII strings are returned as-is.
	 */
	private static String mimeEncodeIfNeeded( String value)
	{
		if( value == null) return "";
		for( int i = 0; i < value.length(); i++)
		{
			if( value.charAt( i) > 127)
			{
				// Encode the whole string as a single Base64 encoded-word
				String b64 = Base64.getEncoder().encodeToString( value.getBytes( StandardCharsets.UTF_8));
				return "=?utf-8?B?" + b64 + "?=";
			}
		}
		return value;
	}
}
