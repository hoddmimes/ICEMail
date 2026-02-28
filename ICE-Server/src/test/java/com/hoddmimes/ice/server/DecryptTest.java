package com.hoddmimes.ice.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class DecryptTest {

    private static final String BEGIN_MARKER = "-----BEGIN ICE ENCRYPTED MESSAGE-----";
    private static final String END_MARKER = "-----END ICE ENCRYPTED MESSAGE-----";
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /**
     * Reads an ICE encrypted message file, extracts the Base64-encoded JSON payload
     * between the BEGIN/END markers.
     */
    private static String readEncryptedPayload(String filePath) throws IOException {
        String content = Files.readString(Path.of(filePath));

        int beginIdx = content.indexOf(BEGIN_MARKER);
        int endIdx = content.indexOf(END_MARKER);
        if (beginIdx < 0 || endIdx < 0) {
            throw new IllegalArgumentException("File does not contain ICE encrypted message markers");
        }

        String base64Block = content.substring(beginIdx + BEGIN_MARKER.length(), endIdx).trim();
        // Remove any whitespace/newlines within the Base64 block
        return base64Block.replaceAll("\\s+", "");
    }

    /**
     * Decrypts an ICE encrypted message using the given password.
     *
     * Steps:
     * 1. Base64-decode the payload to get a JSON string with salt, iv, ciphertext
     * 2. Derive a 256-bit AES key from the password using PBKDF2WithHmacSHA256
     * 3. Decrypt the ciphertext using AES-256-GCM
     */
    public static String decrypt(String base64Payload, String password) throws Exception {
        // Decode the outer Base64 to get the JSON string
        byte[] jsonBytes = Base64.getDecoder().decode(base64Payload);
        String jsonStr = new String(jsonBytes, StandardCharsets.UTF_8);

        // Parse the JSON structure
        JsonObject json = JsonParser.parseString(jsonStr).getAsJsonObject();
        byte[] salt = Base64.getDecoder().decode(json.get("salt").getAsString());
        byte[] iv = Base64.getDecoder().decode(json.get("iv").getAsString());
        byte[] ciphertext = Base64.getDecoder().decode(json.get("ciphertext").getAsString());

        // Derive AES-256 key from password using PBKDF2
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbkdfKey = keyFactory.generateSecret(keySpec);
        SecretKeySpec aesKey = new SecretKeySpec(pbkdfKey.getEncoded(), "AES");
        keySpec.clearPassword();

        // Decrypt using AES-256-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: DecryptTest <encrypted-file> <password>");
            System.exit(1);
        }

        String filePath = args[0];
        String password = args[1];

        try {
            String base64Payload = readEncryptedPayload(filePath);
            String plaintext = decrypt(base64Payload, password);
            System.out.println(plaintext);
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
