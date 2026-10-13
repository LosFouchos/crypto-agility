package fr.memoire.crypto;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

public final class EcdsaSignature {

    // Paramètres écrits en dur, comme pour les autres briques
    private static final String CURVE = "secp256r1";
    private static final String ALGORITHM = "SHA256withECDSA";

    private EcdsaSignature() { }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        return generator.generateKeyPair();
    }

    //Signe avec la clé PRIVÉE
    public static byte[] sign(PrivateKey privateKey, byte[] data)
            throws GeneralSecurityException {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(data, "Data cannot be null");

        Signature signer = Signature.getInstance(ALGORITHM);
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    // Vérifie avec la clé PUBLIQUE ; renvoie false pour toute signature invalide
    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature)
            throws GeneralSecurityException {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");

        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(data);
        try {
            return verifier.verify(signature);
        } catch (SignatureException e) {
            return false;
        }
    }
}