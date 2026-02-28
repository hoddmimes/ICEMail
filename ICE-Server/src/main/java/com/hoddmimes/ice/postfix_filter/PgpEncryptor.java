package com.hoddmimes.ice.postfix_filter;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class PgpEncryptor {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Encrypt plaintext using the given armored PGP public key.
     * No compression is applied — the literal data is encrypted directly.
     *
     * @param plaintext        the text to encrypt
     * @param armoredPublicKey the recipient's armored PGP public key
     * @return armored PGP message string
     */
    public static String encrypt(String plaintext, String armoredPublicKey) throws Exception {
        PGPPublicKey encryptionKey = findEncryptionKey(armoredPublicKey);

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // Wrap plaintext in a literal data packet (no compression)
        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        OutputStream litStream = literalGen.open(literalOut, PGPLiteralData.UTF8, "msg.txt",
                plaintextBytes.length, new Date());
        litStream.write(plaintextBytes);
        litStream.close();
        literalOut.close();

        byte[] literalData = literalOut.toByteArray();

        // Encrypt the literal data
        JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);

        PGPEncryptedDataGenerator encDataGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encDataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(encryptedOut);
        OutputStream encStream = encDataGen.open(armoredOut, literalData.length);
        encStream.write(literalData);
        encStream.close();
        armoredOut.close();

        return encryptedOut.toString(StandardCharsets.UTF_8.name());
    }

    /**
     * Find the encryption subkey from an armored public key.
     * Falls back to the master key if no encryption subkey is found.
     */
    private static PGPPublicKey findEncryptionKey(String armoredPublicKey) throws Exception {
        InputStream keyIn = new ByteArrayInputStream(armoredPublicKey.getBytes(StandardCharsets.UTF_8));
        InputStream decoderStream = PGPUtil.getDecoderStream(keyIn);
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(decoderStream, new BcKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> ringIterator = keyRings.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPPublicKeyRing keyRing = ringIterator.next();
            Iterator<PGPPublicKey> keyIterator = keyRing.getPublicKeys();

            PGPPublicKey masterKey = null;
            while (keyIterator.hasNext()) {
                PGPPublicKey key = keyIterator.next();
                if (key.isEncryptionKey()) {
                    if (!key.isMasterKey()) {
                        return key; // Prefer encryption subkey
                    }
                    if (masterKey == null) {
                        masterKey = key;
                    }
                }
            }
            if (masterKey != null) {
                return masterKey;
            }
        }

        throw new IllegalArgumentException("No encryption key found in the provided public key");
    }
}
