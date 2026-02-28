package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

public class IpMatcher {

    public static boolean matches(String ipAddress, JsonArray ipPatterns) {
        for (JsonElement pattern : ipPatterns) {
            String patternStr = pattern.getAsString();
            if (matchesPattern(ipAddress, patternStr)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesPattern(String ipAddress, String pattern) {
        // Match wildcard "*"
        if (pattern.equals("*")) {
            return true;
        }

        // Split the IP address and pattern into segments
        String[] ipSegments = ipAddress.split("\\.");
        String[] patternSegments = pattern.split("\\.");

        if (ipSegments.length != 4 || patternSegments.length != 4) {
            return false; // Invalid IP format
        }

        // Check each segment for matches or wildcards
        for (int i = 0; i < 4; i++) {
            if (!patternSegments[i].equals("*") && !patternSegments[i].equals(ipSegments[i])) {
                return false; // No match
            }
        }

        return true; // All segments match
    }

    public static void main(String[] args) {
        JsonArray ipPatterns = new JsonArray();
        ipPatterns.add(new JsonPrimitive("192.168.42.*"));
        ipPatterns.add(new JsonPrimitive("192.*.42.*"));
        ipPatterns.add(new JsonPrimitive("*"));

        // Test cases
        System.out.println(matches("192.168.42.10", ipPatterns)); // true
        System.out.println(matches("192.168.43.10", ipPatterns)); // false
        System.out.println(matches("192.50.42.10", ipPatterns));  // true
        System.out.println(matches("10.0.0.1", ipPatterns));      // true
    }
}
