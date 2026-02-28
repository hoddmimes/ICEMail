package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.sun.tools.javac.Main;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class JAux
{
    static String PROFILE_USERNAME = "username";
    static String PROFILE_PASSWORD = "password";
    static String PROFILE_LAST_SEEN = "lastseen";
    static String PROFILE_PRIVATE_KEY = "privatekey";
    static String PROFILE_PUBLIC_KEY = "publickey";
    static String PROFILE_CONFORMATION_MAIL = "confirmationmail";
    static String PROFILE_CONFORMATION = "confirmation";


    public static String profileToString( JsonObject jProfile ) {
        if (jProfile == null) {
            return "<null>";
        }
        return "[ "  + Profile.USERNAME + " : " + jProfile.get( Profile.USERNAME) +
                Profile.CONFIRMATION_MAIL + " : " + jProfile.get( Profile.CONFIRMATION_MAIL) +
                Profile.LAST_SEEN + " : " + jProfile.get( Profile.LAST_SEEN) +
                Profile.CONFIRMED + " : " + jProfile.get( Profile.CONFIRMED) +
                Profile.CREATED + " : " + jProfile.get( Profile.CREATED) + " ]";
    }

    static String B64Encode( String pString ) {
        return Base64.getEncoder().encodeToString(pString.getBytes());
    }
    static String B64Decode( String pString ) {
        return new String(Base64.getDecoder().decode(pString.getBytes()));
    }

    public static String statusResponse(int pStatusCode, String pMessage ) {
        JsonObject stsrsp = new JsonObject();

        boolean tSuccess = ((pStatusCode >= 200) && (pStatusCode < 400)) ? true : false;
        stsrsp.addProperty("success", tSuccess );
        stsrsp.addProperty("message",  pMessage);
        stsrsp.add("data", JsonNull.INSTANCE);
        return stsrsp.toString();
    }

    public static String statusResponse(JsonObject jObject ) {
        JsonObject stsrsp = new JsonObject();
        stsrsp.addProperty("success", true );
        stsrsp.addProperty("message", "OK");
        stsrsp.add("data", jObject );
        return stsrsp.toString();
    }

    public static String statusResponse(JsonArray jArray ) {
        JsonObject stsrsp = new JsonObject();
        stsrsp.addProperty("success", true );
        stsrsp.addProperty("message", "OK");
        stsrsp.add("data", jArray );
        return stsrsp.toString();
    }


    public static boolean runningWithinIntelliJ() {
       String intelliJ = System.getProperty("intelliJ");
       if (intelliJ == null) {
           return false;
       }
       return Boolean.parseBoolean(intelliJ );
    }

    public static String PBKDF2(String username, String password) throws Exception {
        char[] passwordChars = password.toCharArray();
        byte[] salt = username.toLowerCase().getBytes(StandardCharsets.UTF_8);

        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 100_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static String sha256hash(String password) {
        try {
            // Create a MessageDigest instance for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Hash the password
            byte[] hashBytes = digest.digest(password.getBytes());

            // Convert byte array to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0'); // Append leading zero
                }
                hexString.append(hex);
            }

            return hexString.toString(); // Return the hashed password as a hex string
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); // Handle the exception
        }
    }
}
