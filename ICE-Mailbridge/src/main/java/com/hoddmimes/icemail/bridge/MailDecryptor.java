/**
 * PGP-based decryption implementation.
 *
 * At login time, initialize() is called with:
 *   - encryptedPrivateKey: Base64( PGP-symmetric-encrypted( armored-PGP-secret-key ) )
 *   - plaintextPassword:   the user's plaintext password
 *
 * The password is used twice:
 *   1. To decrypt the outer PGP symmetric wrapper → armored PGP secret key
 *   2. As the PGP key passphrase to unlock the secret key for decryption
 *
 * Mail bodies are decrypted by replacing the PGP MESSAGE block with plaintext.
 * Encrypted subjects (ENC:ICE:<base64>) are decrypted in ENVELOPE and header lines.
 */

package com.hoddmimes.icemail.bridge;

import org.apache.logging.log4j.Level;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class MailDecryptor implements Decryptor
{
	static
	{
		if( Security.getProvider( BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider( new BouncyCastleProvider());
		}
	}

	// Pattern to match encrypted subject: ENC:ICE:<base64 encrypted data>
	private static final Pattern ENCRYPTED_SUBJECT_PATTERN =
		Pattern.compile( ImapResponseHandler.ENCRYPTED_SUBJECT_PREFIX + "([A-Za-z0-9+/=]+)");

	// Pattern to match Subject header line
	private static final Pattern SUBJECT_HEADER_PATTERN =
		Pattern.compile( "(Subject:\\s*)" + ImapResponseHandler.ENCRYPTED_SUBJECT_PREFIX + "([A-Za-z0-9+/=]+)");

	// Pattern to match PGP encrypted message block
	private static final Pattern PGP_MESSAGE_PATTERN =
		Pattern.compile( "-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----", Pattern.DOTALL);

	private String armoredPrivateKey = null;
	private String armoredPublicKey = null;
	private String passphrase = null;
	private boolean ready = false;

	public MailDecryptor()
	{
	}

	@Override
	public void initialize( String encryptedPrivateKey, String plaintextPassword, String publicKey)
	{
		if( encryptedPrivateKey == null || plaintextPassword == null)
		{
			MailBridge.log( Level.WARN, "MailDecryptor.initialize: null arguments, decryption disabled");
			return;
		}

		try
		{
			// 1. Base64-decode the encrypted private key blob
			byte[] encryptedBytes = Base64.getDecoder().decode( encryptedPrivateKey);

			// 2. PGP-decrypt the outer symmetric wrapper with the plaintext password
			String armored = pgpSymmetricDecrypt( encryptedBytes, plaintextPassword);
			if( armored == null)
			{
				MailBridge.log( Level.ERROR, "MailDecryptor: failed to decrypt private key wrapper");
				return;
			}

			this.armoredPrivateKey = armored;
			this.armoredPublicKey = publicKey;
			this.passphrase = plaintextPassword;
			this.ready = true;
			MailBridge.log( Level.INFO, "MailDecryptor: private key unlocked successfully");
		}
		catch( Throwable e)
		{
			MailBridge.log( Level.ERROR, "MailDecryptor.initialize failed", e);
		}
	}

	@Override
	public boolean isReady()
	{
		return ready;
	}

	@Override
	public String decryptSubjectInEnvelope( String envelopeLine)
	{
		Matcher matcher = ENCRYPTED_SUBJECT_PATTERN.matcher( envelopeLine);
		if( !matcher.find())
		{
			return envelopeLine;
		}

		if( !isReady())
		{
			return envelopeLine;
		}

		String encryptedData = matcher.group( 1);
		String decryptedSubject = decryptSubjectData( encryptedData);
		if( decryptedSubject == null)
		{
			return envelopeLine;
		}

		return envelopeLine.replace(
			ImapResponseHandler.ENCRYPTED_SUBJECT_PREFIX + encryptedData,
			decryptedSubject);
	}

	@Override
	public String decryptSubjectInHeader( String headerLine)
	{
		Matcher matcher = SUBJECT_HEADER_PATTERN.matcher( headerLine);
		if( !matcher.find())
		{
			return headerLine;
		}

		if( !isReady())
		{
			return headerLine;
		}

		String prefix = matcher.group( 1);
		String encryptedData = matcher.group( 2);

		String decryptedSubject = decryptSubjectData( encryptedData);
		if( decryptedSubject == null)
		{
			return headerLine;
		}

		return matcher.replaceFirst( prefix + decryptedSubject);
	}

	@Override
	public String decryptBody( String content)
	{
		if( !isReady())
		{
			return content;
		}

		Matcher matcher = PGP_MESSAGE_PATTERN.matcher( content);
		if( !matcher.find())
		{
			return content;
		}

		String pgpBlock = matcher.group( 0);
		MailBridge.log( Level.DEBUG, "MailDecryptor: found PGP block, decrypting body");

		try
		{
			String decryptedBody = pgpDecrypt( pgpBlock, armoredPrivateKey, passphrase);
			if( decryptedBody == null)
			{
				return content;
			}
			return content.replace( pgpBlock, decryptedBody);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "MailDecryptor: body decryption failed", e);
			return content;
		}
	}

	/**
	 * Decrypt the outer PGP symmetric-password-encrypted wrapper.
	 * The wrapper was created by OpenPGP.js: openpgp.encrypt({ passwords: [password] }).
	 * The plaintext inside is the armored PGP secret key.
	 */
	private String pgpSymmetricDecrypt( byte[] encryptedData, String password) throws Exception
	{
		// Determine if the data is binary PGP (high bit set on first byte) or ASCII-armored.
		// Use ArmoredInputStream directly for armored data to avoid loading PGPUtil, whose
		// static initialiser references org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers —
		// a class removed in bcprov 1.80 — which causes NoClassDefFoundError in a fat JAR.
		boolean isBinary = (encryptedData[0] & 0x80) != 0;
		MailBridge.log( Level.DEBUG, "pgpSymmetricDecrypt: data length=" + encryptedData.length + " format=" + (isBinary ? "binary" : "armored"));
		InputStream in = isBinary
			? new ByteArrayInputStream( encryptedData)
			: new ArmoredInputStream( new ByteArrayInputStream( encryptedData));

		PGPObjectFactory factory = new PGPObjectFactory( in, new BcKeyFingerprintCalculator());

		Object obj = factory.nextObject();
		PGPEncryptedDataList encList;
		if( obj instanceof PGPEncryptedDataList)
		{
			encList = (PGPEncryptedDataList) obj;
		}
		else
		{
			encList = (PGPEncryptedDataList) factory.nextObject();
		}

		for( PGPEncryptedData ed : encList)
		{
			if( ed instanceof PGPPBEEncryptedData)
			{
				PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) ed;
				InputStream decryptedStream = pbe.getDataStream(
					new BcPBEDataDecryptorFactory( password.toCharArray(), new BcPGPDigestCalculatorProvider()));

				PGPObjectFactory plainFactory = new PGPObjectFactory( decryptedStream, new BcKeyFingerprintCalculator());
				Object plainObj = plainFactory.nextObject();

				if( plainObj instanceof PGPLiteralData)
				{
					PGPLiteralData ld = (PGPLiteralData) plainObj;
					byte[] data = ld.getInputStream().readAllBytes();
					return new String( data, StandardCharsets.UTF_8);
				}
				else if( plainObj instanceof PGPCompressedData)
				{
					PGPCompressedData cd = (PGPCompressedData) plainObj;
					PGPObjectFactory compFactory = new PGPObjectFactory( cd.getDataStream(), new BcKeyFingerprintCalculator());
					Object compObj = compFactory.nextObject();
					if( compObj instanceof PGPLiteralData)
					{
						PGPLiteralData ld = (PGPLiteralData) compObj;
						byte[] data = ld.getInputStream().readAllBytes();
						return new String( data, StandardCharsets.UTF_8);
					}
				}
			}
		}

		MailBridge.log( Level.WARN, "pgpSymmetricDecrypt: no PBE encrypted data found in PGP object");
		return null;
	}

	/**
	 * Decrypt a PGP public-key-encrypted message using the user's private key.
	 *
	 * @param armoredMessage    Full PGP MESSAGE block (armored)
	 * @param armoredSecretKey  Armored PGP secret key ring
	 * @param passphrase        Passphrase to unlock the secret key
	 * @return Decrypted plaintext, or null on failure
	 */
	private String pgpDecrypt( String armoredMessage, String armoredSecretKey, String passphrase) throws Exception
	{
		// Load secret key ring
		InputStream keyIn = new ArmoredInputStream(
			new ByteArrayInputStream( armoredSecretKey.getBytes( StandardCharsets.UTF_8)));
		PGPSecretKeyRingCollection secretKeyRings =
			new PGPSecretKeyRingCollection( keyIn, new BcKeyFingerprintCalculator());

		// Parse the encrypted message
		InputStream msgIn = new ArmoredInputStream(
			new ByteArrayInputStream( armoredMessage.getBytes( StandardCharsets.UTF_8)));
		PGPObjectFactory factory = new PGPObjectFactory( msgIn, new BcKeyFingerprintCalculator());

		Object obj = factory.nextObject();
		PGPEncryptedDataList encList;
		if( obj instanceof PGPEncryptedDataList)
		{
			encList = (PGPEncryptedDataList) obj;
		}
		else
		{
			encList = (PGPEncryptedDataList) factory.nextObject();
		}

		// Find the public-key encrypted session key that matches our secret key
		PGPPrivateKey privateKey = null;
		PGPPublicKeyEncryptedData pked = null;

		Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
		while( it.hasNext())
		{
			PGPEncryptedData ed = it.next();
			if( ed instanceof PGPPublicKeyEncryptedData)
			{
				PGPPublicKeyEncryptedData candidate = (PGPPublicKeyEncryptedData) ed;
				PGPSecretKey secretKey = secretKeyRings.getSecretKey( candidate.getKeyID());
				if( secretKey != null)
				{
					privateKey = secretKey.extractPrivateKey(
						new BcPBESecretKeyDecryptorBuilder( new BcPGPDigestCalculatorProvider())
							.build( passphrase.toCharArray()));
					pked = candidate;
					break;
				}
			}
		}

		if( privateKey == null || pked == null)
		{
			MailBridge.log( Level.ERROR, "MailDecryptor: no matching private key found for PGP message");
			return null;
		}

		// Decrypt the session key and message data
		InputStream decryptedStream = pked.getDataStream( new BcPublicKeyDataDecryptorFactory( privateKey));
		PGPObjectFactory plainFactory = new PGPObjectFactory( decryptedStream, new BcKeyFingerprintCalculator());

		Object plainObj = plainFactory.nextObject();

		// Handle optional compression layer
		if( plainObj instanceof PGPCompressedData)
		{
			PGPCompressedData cd = (PGPCompressedData) plainObj;
			plainFactory = new PGPObjectFactory( cd.getDataStream(), new BcKeyFingerprintCalculator());
			plainObj = plainFactory.nextObject();
		}

		if( plainObj instanceof PGPLiteralData)
		{
			PGPLiteralData ld = (PGPLiteralData) plainObj;
			byte[] plainBytes = ld.getInputStream().readAllBytes();
			MailBridge.log( Level.DEBUG, "MailDecryptor: body decrypted successfully");
			return new String( plainBytes, StandardCharsets.UTF_8);
		}

		MailBridge.log( Level.ERROR, "MailDecryptor: unexpected PGP object type after decryption");
		return null;
	}

	/**
	 * Encrypt plaintext using the user's PGP public key (extracted from the stored private key).
	 * Returns an armored PGP message block suitable for storage as a sent-mail body.
	 * Used by the SMTP proxy to save an encrypted copy in the user's Sent folder.
	 *
	 * @param plaintext The plaintext to encrypt (mail body)
	 * @return Armored PGP MESSAGE block, or null on failure
	 */
	public String encryptForSentFolder( String plaintext)
	{
		if( !ready || armoredPublicKey == null)
		{
			MailBridge.log( Level.WARN, "encryptForSentFolder: decryptor not ready or no public key");
			return null;
		}
		return encryptWithPublicKey( plaintext, armoredPublicKey);
	}

	/**
	 * Encrypt plaintext using the given armored PGP public key.
	 * Static so callers that already have the public key (e.g. SmtpProxyChannel)
	 * can encrypt without instantiating or initializing a full MailDecryptor.
	 */
	public static String encryptWithPublicKey( String plaintext, String armoredPublicKey)
	{
		if( armoredPublicKey == null)
		{
			MailBridge.log( Level.WARN, "encryptWithPublicKey: no public key provided");
			return null;
		}

		try
		{
			// Load the sender's public key ring directly — no secret key ring needed
			InputStream keyIn = new ArmoredInputStream(
				new ByteArrayInputStream( armoredPublicKey.getBytes( StandardCharsets.UTF_8)));
			PGPPublicKeyRingCollection publicKeyRings =
				new PGPPublicKeyRingCollection( keyIn, new BcKeyFingerprintCalculator());

			PGPPublicKey encryptionKey = null;
			outer:
			for( Iterator<PGPPublicKeyRing> rings = publicKeyRings.getKeyRings(); rings.hasNext(); )
			{
				PGPPublicKeyRing ring = rings.next();
				for( Iterator<PGPPublicKey> keys = ring.getPublicKeys(); keys.hasNext(); )
				{
					PGPPublicKey pk = keys.next();
					if( pk.isEncryptionKey())
					{
						encryptionKey = pk;
						break outer;
					}
				}
			}

			if( encryptionKey == null)
			{
				MailBridge.log( Level.ERROR, "encryptWithPublicKey: no encryption public key found");
				return null;
			}

			byte[] plaintextBytes = plaintext.getBytes( StandardCharsets.UTF_8);
			ByteArrayOutputStream encOut = new ByteArrayOutputStream();
			ArmoredOutputStream armoredOut = new ArmoredOutputStream( encOut);

			BcPGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder( PGPEncryptedData.AES_256)
				.setWithIntegrityPacket( true)
				.setSecureRandom( new SecureRandom());

			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator( encBuilder);
			encGen.addMethod( new BcPublicKeyKeyEncryptionMethodGenerator( encryptionKey));

			PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();
			try( OutputStream encStream = encGen.open( armoredOut, new byte[1 << 16]))
			{
				try( OutputStream ldStream = ldGen.open( encStream, PGPLiteralData.BINARY, "",
					plaintextBytes.length, new Date()))
				{
					ldStream.write( plaintextBytes);
				}
			}
			armoredOut.close();

			MailBridge.log( Level.DEBUG, "encryptForSentFolder: body encrypted successfully");
			return encOut.toString( StandardCharsets.UTF_8);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "encryptForSentFolder failed", e);
			return null;
		}
	}

	/**
	 * Decrypt a base64-encoded encrypted subject.
	 * The subject is PGP-encrypted with the user's public key (same as the body).
	 */
	private String decryptSubjectData( String encryptedBase64)
	{
		try
		{
			// The encrypted subject is a base64-encoded PGP message
			byte[] pgpBytes = Base64.getDecoder().decode( encryptedBase64);
			String armoredSubject = "-----BEGIN PGP MESSAGE-----\n\n" +
				Base64.getEncoder().encodeToString( pgpBytes) +
				"\n-----END PGP MESSAGE-----\n";

			return pgpDecrypt( armoredSubject, armoredPrivateKey, passphrase);
		}
		catch( Exception e)
		{
			MailBridge.log( Level.ERROR, "MailDecryptor: subject decryption failed", e);
			return null;
		}
	}
}
