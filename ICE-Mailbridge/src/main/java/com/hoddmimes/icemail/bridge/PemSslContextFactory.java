/**
 * Factory for creating SSLContext from PEM certificate and key files.
 */

package com.hoddmimes.icemail.bridge;

import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedReader;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

import org.apache.logging.log4j.Level;

public class PemSslContextFactory
{
	/**
	 * Create an SSLServerSocketFactory from PEM certificate and key files.
	 *
	 * @param certPath Path to the PEM certificate file
	 * @param keyPath Path to the PEM private key file
	 * @param tlsProtocol TLS protocol version (e.g., "TLSv1.3")
	 * @return SSLServerSocketFactory configured with the certificate and key
	 */
	public static SSLServerSocketFactory createServerSocketFactory( String certPath, String keyPath, String tlsProtocol)
		throws Exception
	{
		// Load certificate chain
		X509Certificate[] certChain = loadCertificateChain( certPath);
		MailBridge.log( Level.INFO, "Loaded " + certChain.length + " certificate(s) from " + certPath);

		// Load private key
		PrivateKey privateKey = loadPrivateKey( keyPath);
		MailBridge.log( Level.INFO, "Loaded private key from " + keyPath);

		// Create KeyStore with the certificate and key
		KeyStore keyStore = KeyStore.getInstance( "JKS");
		keyStore.load( null, null);
		keyStore.setKeyEntry( "mailbridge", privateKey, "".toCharArray(), certChain);

		// Create KeyManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm());
		kmf.init( keyStore, "".toCharArray());

		// Create SSLContext
		SSLContext sslContext = SSLContext.getInstance( tlsProtocol);
		sslContext.init( kmf.getKeyManagers(), null, null);

		return sslContext.getServerSocketFactory();
	}

	/**
	 * Load a certificate chain from a PEM file.
	 * The file may contain multiple certificates (chain).
	 */
	private static X509Certificate[] loadCertificateChain( String certPath) throws Exception
	{
		List<X509Certificate> certs = new ArrayList<>();
		CertificateFactory cf = CertificateFactory.getInstance( "X.509");

		try( BufferedReader reader = new BufferedReader( new FileReader( certPath)))
		{
			StringBuilder certPem = new StringBuilder();
			boolean inCert = false;

			String line;
			while(( line = reader.readLine()) != null)
			{
				if( line.contains( "BEGIN CERTIFICATE"))
				{
					inCert = true;
					certPem = new StringBuilder();
				}
				else if( line.contains( "END CERTIFICATE"))
				{
					inCert = false;
					byte[] certBytes = Base64.getDecoder().decode( certPem.toString());
					X509Certificate cert = (X509Certificate) cf.generateCertificate(
						new java.io.ByteArrayInputStream( certBytes));
					certs.add( cert);
				}
				else if( inCert)
				{
					certPem.append( line.trim());
				}
			}
		}

		if( certs.isEmpty())
		{
			throw new IOException( "No certificates found in " + certPath);
		}

		return certs.toArray( new X509Certificate[0]);
	}

	/**
	 * Load a private key from a PEM file.
	 * Supports PKCS#8 format (BEGIN PRIVATE KEY) and attempts RSA PKCS#1 (BEGIN RSA PRIVATE KEY).
	 */
	private static PrivateKey loadPrivateKey( String keyPath) throws Exception
	{
		StringBuilder keyPem = new StringBuilder();
		boolean inKey = false;
		boolean isPkcs1 = false;

		try( BufferedReader reader = new BufferedReader( new FileReader( keyPath)))
		{
			String line;
			while(( line = reader.readLine()) != null)
			{
				if( line.contains( "BEGIN PRIVATE KEY"))
				{
					inKey = true;
					isPkcs1 = false;
				}
				else if( line.contains( "BEGIN RSA PRIVATE KEY"))
				{
					inKey = true;
					isPkcs1 = true;
				}
				else if( line.contains( "END PRIVATE KEY") || line.contains( "END RSA PRIVATE KEY"))
				{
					inKey = false;
				}
				else if( inKey)
				{
					keyPem.append( line.trim());
				}
			}
		}

		if( keyPem.length() == 0)
		{
			throw new IOException( "No private key found in " + keyPath);
		}

		byte[] keyBytes = Base64.getDecoder().decode( keyPem.toString());

		if( isPkcs1)
		{
			// Convert PKCS#1 to PKCS#8 format
			keyBytes = convertPkcs1ToPkcs8( keyBytes);
		}

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec( keyBytes);
		KeyFactory kf = KeyFactory.getInstance( "RSA");

		try {
			return kf.generatePrivate( keySpec);
		} catch( Exception e) {
			// Try EC if RSA fails
			kf = KeyFactory.getInstance( "EC");
			return kf.generatePrivate( keySpec);
		}
	}

	/**
	 * Convert PKCS#1 RSA private key to PKCS#8 format.
	 */
	private static byte[] convertPkcs1ToPkcs8( byte[] pkcs1Bytes)
	{
		// PKCS#8 header for RSA key
		byte[] pkcs8Header = {
			0x30, (byte) 0x82, 0x00, 0x00, // SEQUENCE, length placeholder
			0x02, 0x01, 0x00,              // INTEGER 0 (version)
			0x30, 0x0d,                    // SEQUENCE
			0x06, 0x09,                    // OID
			0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, // RSA OID
			0x05, 0x00,                    // NULL
			0x04, (byte) 0x82, 0x00, 0x00  // OCTET STRING, length placeholder
		};

		int totalLength = pkcs8Header.length + pkcs1Bytes.length;
		byte[] pkcs8Bytes = new byte[totalLength];

		System.arraycopy( pkcs8Header, 0, pkcs8Bytes, 0, pkcs8Header.length);
		System.arraycopy( pkcs1Bytes, 0, pkcs8Bytes, pkcs8Header.length, pkcs1Bytes.length);

		// Fix lengths
		int seqLength = totalLength - 4;
		pkcs8Bytes[2] = (byte) ((seqLength >> 8) & 0xff);
		pkcs8Bytes[3] = (byte) (seqLength & 0xff);

		int octetLength = pkcs1Bytes.length;
		pkcs8Bytes[pkcs8Header.length - 2] = (byte) ((octetLength >> 8) & 0xff);
		pkcs8Bytes[pkcs8Header.length - 1] = (byte) (octetLength & 0xff);

		return pkcs8Bytes;
	}
}
