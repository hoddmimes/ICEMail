/**
 * Handles parsing and processing of IMAP responses from the server.
 * Identifies FETCH responses and routes them through decryption.
 */

package com.hoddmimes.icemail.bridge;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.Level;

public class ImapResponseHandler
{
	// Pattern to match FETCH responses: * <seq> FETCH (...)
	private static final Pattern FETCH_PATTERN = Pattern.compile("^\\* (\\d+) FETCH \\((.*)$");

	// Pattern to match ENVELOPE in FETCH response
	private static final Pattern ENVELOPE_PATTERN = Pattern.compile("ENVELOPE \\(([^)]+)\\)");

	// Pattern to match literal size: {<size>}
	private static final Pattern LITERAL_PATTERN = Pattern.compile("\\{(\\d+)\\}$");

	// Prefix used to identify encrypted subjects
	public static final String ENCRYPTED_SUBJECT_PREFIX = "ENC:ICE:";

	private final Decryptor decryptor;

	// State for multi-line FETCH response parsing
	private boolean inFetchResponse = false;
	private StringBuilder fetchBuffer = new StringBuilder();
	private int literalBytesRemaining = 0;

	public ImapResponseHandler( Decryptor decryptor)
	{
		this.decryptor = decryptor;
	}

	/**
	 * Process a line from the IMAP server.
	 * Returns the potentially modified line to send to the client.
	 */
	public String processServerResponse( String line)
	{
		// Check if we're reading literal data
		if( literalBytesRemaining > 0)
		{
			return handleLiteralData( line);
		}

		// Check if this is a FETCH response
		Matcher fetchMatcher = FETCH_PATTERN.matcher( line);
		if( fetchMatcher.find())
		{
			return handleFetchResponse( line, fetchMatcher);
		}

		// Not a FETCH response, pass through unchanged
		return line;
	}

	/**
	 * Handle the start of a FETCH response.
	 */
	private String handleFetchResponse( String line, Matcher matcher)
	{
		String sequenceNumber = matcher.group(1);
		String fetchData = matcher.group(2);

		MailBridge.log( Level.DEBUG, "FETCH response for message " + sequenceNumber);

		// Check for a literal {size} FIRST — if present, we must buffer the body
		// regardless of whether the header line also contains encrypted content.
		Matcher literalMatcher = LITERAL_PATTERN.matcher( line);
		if( literalMatcher.find())
		{
			literalBytesRemaining = Integer.parseInt( literalMatcher.group(1));
			inFetchResponse = true;
			fetchBuffer = new StringBuilder();
			fetchBuffer.append( line).append( "\r\n");
			MailBridge.log( Level.DEBUG, "FETCH has literal of " + literalBytesRemaining + " bytes, buffering for decryption");
			return null; // Hold this line until the full literal is received
		}

		// No literal — process any encrypted content in the FETCH line itself (e.g. ENVELOPE subject)
		if( containsEncryptedContent( fetchData))
		{
			return processFetchData( line);
		}

		return line;
	}

	/**
	 * Handle literal data (body content).
	 * readLine() strips the line ending, so we re-add \r\n when buffering
	 * and account for those 2 bytes in the remaining count.
	 */
	private String handleLiteralData( String line)
	{
		fetchBuffer.append( line).append( "\r\n");
		literalBytesRemaining -= (line.length() + 2);

		if( literalBytesRemaining <= 0)
		{
			// Literal complete, process the full FETCH response
			inFetchResponse = false;
			String fullResponse = fetchBuffer.toString();
			fetchBuffer = new StringBuilder();

			return processCompleteFetchResponse( fullResponse);
		}

		// Still reading literal, buffer it
		return null; // Signal to buffer, don't send yet
	}

	/**
	 * Check if the FETCH data contains items that may have encrypted content.
	 */
	private boolean containsEncryptedContent( String fetchData)
	{
		// Check for ENVELOPE (contains subject)
		if( fetchData.contains("ENVELOPE"))
			return true;

		// Check for BODY sections that may contain headers or body
		if( fetchData.contains("BODY["))
			return true;

		// Check for RFC822 variants
		if( fetchData.contains("RFC822"))
			return true;

		return false;
	}

	/**
	 * Process FETCH data that may contain encrypted subject in ENVELOPE.
	 */
	private String processFetchData( String line)
	{
		String result = line;

		// Handle encrypted subject in ENVELOPE
		result = decryptEnvelopeSubject( result);

		// Handle encrypted subject in raw headers
		result = decryptHeaderSubject( result);

		return result;
	}

	/**
	 * Process a complete FETCH response including literal body data.
	 */
	private String processCompleteFetchResponse( String fullResponse)
	{
		String result = fullResponse;

		// Decrypt subject if present
		result = decryptEnvelopeSubject( result);
		result = decryptHeaderSubject( result);

		// Decrypt body content
		result = decryptBody( result);

		// Update the IMAP literal {N} byte count to match the (possibly changed) content size.
		// Strict clients like iOS Mail read exactly N bytes; a stale count corrupts the stream.
		result = updateLiteralSizeInResponse( result);

		return result;
	}

	/**
	 * Recalculate and update the {N} literal byte count after decryption.
	 * The literal content is everything after the first CRLF (the header line).
	 */
	private String updateLiteralSizeInResponse( String response)
	{
		int firstCrlf = response.indexOf( "\r\n");
		if( firstCrlf < 0)
			return response;

		String headerLine = response.substring( 0, firstCrlf);
		Matcher literalMatcher = LITERAL_PATTERN.matcher( headerLine);
		if( !literalMatcher.find())
			return response;

		String literalContent = response.substring( firstCrlf + 2);
		int oldSize = Integer.parseInt( literalMatcher.group(1));
		int newSize = literalContent.getBytes( StandardCharsets.UTF_8).length;

		if( oldSize != newSize)
		{
			MailBridge.log( Level.DEBUG, "Updated FETCH literal size after decryption: {" + oldSize + "} -> {" + newSize + "}");
			String newHeader = literalMatcher.replaceFirst( "{" + newSize + "}");
			return newHeader + "\r\n" + literalContent;
		}

		return response;
	}

	/**
	 * Decrypt the subject within an ENVELOPE response.
	 * ENVELOPE format: (date subject from sender reply-to to cc bcc in-reply-to message-id)
	 */
	private String decryptEnvelopeSubject( String line)
	{
		if( !line.contains("ENVELOPE"))
			return line;

		// Entry point for ENVELOPE subject decryption (passes through if decryption not configured)
		return decryptor.decryptSubjectInEnvelope( line);
	}

	/**
	 * Decrypt the subject in raw email headers (BODY[HEADER], RFC822.HEADER, etc.)
	 * Looks for: Subject: ENC:ICE:...
	 */
	private String decryptHeaderSubject( String line)
	{
		if( !line.contains("Subject:"))
			return line;

		// Entry point for header subject decryption (passes through if decryption not configured)
		return decryptor.decryptSubjectInHeader( line);
	}

	/**
	 * Decrypt the email body content.
	 */
	private String decryptBody( String content)
	{
		// Entry point for body decryption (passes through if decryption not configured)
		return decryptor.decryptBody( content);
	}

	/**
	 * Update literal byte count in IMAP response after decryption.
	 * When content size changes, the {size} literal must be updated.
	 *
	 * @param original Original response with {oldSize}
	 * @param newContent New content after decryption
	 * @return Response with updated {newSize}
	 */
	public String updateLiteralSize( String original, String newContent)
	{
		Matcher matcher = LITERAL_PATTERN.matcher( original);
		if( matcher.find())
		{
			int newSize = newContent.length();
			return matcher.replaceFirst("{" + newSize + "}");
		}
		return original;
	}
}
