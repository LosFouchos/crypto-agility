package fr.memoire.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public final class AesGcm {

    // Paramètres écrits en dur
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BITS = 256;
    private static final int NONCE_SIZE_BYTES = 12;
    private static final int TAG_SIZE_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcm() { }

    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE_BITS, RANDOM);
        return generator.generateKey();
    }

    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        Objects.requireNonNull(key, "Key cannot be null");
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(aad, "AAD cannot be null");

        //Un nonce neuf et aléatoire à chaque chiffrement
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        RANDOM.nextBytes(nonce);

        // Chiffrement
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE_BITS, nonce));
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[NONCE_SIZE_BYTES + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE_BYTES);
        System.arraycopy(ciphertext, 0, result, NONCE_SIZE_BYTES, ciphertext.length);
        return result;
    }

    public static byte[] decrypt(SecretKey key, byte[] nonceAndCiphertext, byte[] aad)
            throws GeneralSecurityException {
        Objects.requireNonNull(key, "Key cannot be null");
        Objects.requireNonNull(nonceAndCiphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(aad, "AAD cannot be null");


        if (nonceAndCiphertext.length < NONCE_SIZE_BYTES + TAG_SIZE_BITS / 8) {
            throw new IllegalArgumentException("Ciphertext too short");
        }


        byte[] nonce = Arrays.copyOfRange(nonceAndCiphertext, 0, NONCE_SIZE_BYTES);

        //Déchiffrement + vérification d'intégrité
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(nonceAndCiphertext, NONCE_SIZE_BYTES,
                nonceAndCiphertext.length - NONCE_SIZE_BYTES);
    }
}