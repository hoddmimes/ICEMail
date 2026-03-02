package com.hoddmimes.ice.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * ALTCHA proof-of-work CAPTCHA service.
 *
 * The server issues a challenge: { algorithm, challenge, maxnumber, salt, signature }
 * where challenge = SHA-256(salt + secret_number) and
 *       signature = HMAC-SHA256(hmacKey, challenge).
 *
 * The client widget brute-forces the number (0..maxnumber) and submits the payload.
 * Verification checks the HMAC (prevents forged challenges) and re-derives the hash.
 */
public class AltchaService {

    private static final String ALGORITHM = "SHA-256";
    private static final int    MAX_NUMBER = 100_000;

    private final byte[]       mHmacKey;
    private final SecureRandom mRandom = new SecureRandom();

    public AltchaService(String hmacKey) {
        mHmacKey = hmacKey.getBytes(StandardCharsets.UTF_8);
    }

    /** Create a new challenge to send to the browser widget. */
    public JsonObject createChallenge() throws Exception {
        byte[] saltBytes = new byte[12];
        mRandom.nextBytes(saltBytes);
        String salt   = HexFormat.of().formatHex(saltBytes);
        int    number = mRandom.nextInt(MAX_NUMBER) + 1;

        String challenge = sha256hex(salt + number);
        String signature = hmacSha256hex(challenge);

        JsonObject obj = new JsonObject();
        obj.addProperty("algorithm", ALGORITHM);
        obj.addProperty("challenge", challenge);
        obj.addProperty("maxnumber", MAX_NUMBER);
        obj.addProperty("salt",      salt);
        obj.addProperty("signature", signature);
        return obj;
    }

    /**
     * Verify a base64-encoded ALTCHA payload submitted by the client widget.
     * Returns true only when both the HMAC and the PoW solution are valid.
     */
    public boolean verify(String payloadBase64) {
        try {
            String     json    = new String(Base64.getDecoder().decode(payloadBase64), StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(json).getAsJsonObject();

            String algorithm = payload.get("algorithm").getAsString();
            String challenge = payload.get("challenge").getAsString();
            long   number    = payload.get("number").getAsLong();
            String salt      = payload.get("salt").getAsString();
            String signature = payload.get("signature").getAsString();

            if (!ALGORITHM.equals(algorithm))              return false;
            if (!hmacSha256hex(challenge).equals(signature)) return false;
            return sha256hex(salt + number).equals(challenge);
        } catch (Exception e) {
            return false;
        }
    }

    private String sha256hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    private String hmacSha256hex(String input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(mHmacKey, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
    }
}
