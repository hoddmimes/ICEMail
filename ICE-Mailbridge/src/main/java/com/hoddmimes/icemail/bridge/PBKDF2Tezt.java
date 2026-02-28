package com.hoddmimes.icemail.bridge;

public class PBKDF2Tezt {


        public static void main(String[] args) throws Exception {
            PBKDF2Tezt t = new PBKDF2Tezt();
            t.test();
        }

        private void test() {
            String username = "alice";
            String password = "whatever";

            try {
                String hex = PBKDF2Hash.hash(username, password);
                System.out.println("Username: " + username);
                System.out.println("Password: " + password);
                System.out.println("PBKDF2:   " + hex);
            }
            catch( Exception e) {
                e.printStackTrace();
            }
    }
}
