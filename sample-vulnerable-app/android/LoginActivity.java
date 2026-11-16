package com.example.insecurebank;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/*
 * Intentionally INSECURE sample. Each numbered issue is detected by the toolkit
 * (static string/crypto scan) or by the Frida storage audit at runtime.
 *
 * Do not copy this code. It exists to demonstrate findings and remediation.
 */
public class LoginActivity extends Activity {

    // (1) Hardcoded secret in the app bundle  -> SECRET_GOOGLE_API / MASVS-STORAGE-1
    private static final String API_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r";

    // (2) Hardcoded symmetric key  -> SECRET_GENERIC_API
    private static final String secret = "password=SuperSecret123!";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // (3) Sensitive data written to plaintext SharedPreferences -> MASTG-TEST-0001
        SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
        prefs.edit().putString("session_token", fetchToken()).apply();

        storeInsecure("4111111111111111");
    }

    private String fetchToken() { return "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.c2lnbmF0dXJldmFsdWU"; }

    // (4) Weak crypto: DES + ECB + Base64 "obfuscation"  -> CRYPTO_DES / CRYPTO_ECB
    private void storeInsecure(String pan) {
        try {
            SecretKeySpec key = new SecretKeySpec("8bytekey".getBytes(), "DES");
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            String out = Base64.encodeToString(c.doFinal(pan.getBytes()), Base64.DEFAULT);
            getSharedPreferences("cards", MODE_PRIVATE).edit().putString("pan", out).apply();
        } catch (Exception ignored) { }
    }
}
