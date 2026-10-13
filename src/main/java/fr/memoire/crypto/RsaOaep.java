package fr.memoire.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;

public final class RsaOaep {

    private static final int KEY_SIZE_BITS = 3072;
    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private RsaOaep() { }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE_BITS);
        return generator.generateKeyPair();
    }

    // Glisse la clé AES dans l'enveloppe, avec la clé PUBLIQUE
    public static byte[] wrapKey(PublicKey publicKey, SecretKey keyToWrap)
            throws GeneralSecurityException {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(keyToWrap, "Key to wrap cannot be null");

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.WRAP_MODE, publicKey, OAEP_PARAMS);
        return cipher.wrap(keyToWrap);
    }

    // Ouvre l'enveloppe avec la clé PRIVÉE et récupère la clé AES
    public static SecretKey unwrapKey(PrivateKey privateKey, byte[] wrappedKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(wrappedKey, "Wrapped key cannot be null");

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.UNWRAP_MODE, privateKey, OAEP_PARAMS);
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
}