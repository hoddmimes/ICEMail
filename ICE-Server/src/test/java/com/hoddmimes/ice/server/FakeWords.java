package com.hoddmimes.ice.server;

import java.util.Random;

public class FakeWords {
    private static final String[] CONSONANTS = {
            "b", "c", "d", "f", "g", "h", "j", "k", "l", "m",
            "n", "p", "r", "s", "t", "v", "w", "ch", "sh", "th", "gr", "tr", "st", "cl", "bl"
    };

    private static final String[] VOWELS = {
            "a", "e", "i", "o", "u", "ea", "ou", "ie", "ai", "oa"
    };

    private static final String ALPHANUMERIC[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");

    private static final Random rand = new Random();

    public static String generateWord(int pLength) {
        StringBuilder word = new StringBuilder();


        for (int i = 0; i < pLength; i++) {
            word.append(randomElement(CONSONANTS));
            word.append(randomElement(VOWELS));
            // Optional: sometimes add a second consonant
            if (rand.nextDouble() < 0.5) {
                word.append(randomElement(CONSONANTS));
            }
        }

        return word.toString().substring(0, pLength);
    }

    public static String generateString( int pLength) {
        StringBuilder word = new StringBuilder();
        for (int i = 0; i < pLength; i++) {
                word.append(ALPHANUMERIC[rand.nextInt(ALPHANUMERIC.length)]);
        }
        return word.toString();
    }

    private static String randomElement(String[] array) {
        return array[rand.nextInt(array.length)];
    }

    // Main method for testing

    public static void main(String[] args) {
        for (int i = 0; i < 20; i++) {
            System.out.println(generateWord(7)); // 2–3 syllables
        }
    }
}
