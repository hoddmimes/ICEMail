package com.hoddmimes.icemail.bridge;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;

public class PBKDF2Hash
{

    private  static String trimQuotes(String pString) {
        if (pString == null) {
            return null; // Handle null input
        }
        // Trim quotes from both ends
        return pString.replaceAll("^\"|\"$", "").trim();
    }

    public static String hash(String username, String password) throws Exception {


        char[] passwordChars = trimQuotes(password).toCharArray();
        byte[] salt = trimQuotes(username.toLowerCase()).getBytes(StandardCharsets.UTF_8);


        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 100_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        byte[] hash = factory.generateSecret(spec).getEncoded();

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
