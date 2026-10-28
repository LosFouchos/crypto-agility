package fr.memoire.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

// Signature ML-DSA-65 (FIPS 204)
public final class MlDsaScheme implements SignatureScheme {

    public static final String ID = "ML-DSA-65";
    private static final String PARAMETER_SET = "ML-DSA-65";

    private final KeyPair keys;

    public MlDsaScheme(KeyPair keys) throws InvalidKeyException {
        Objects.requireNonNull(keys, "Keys cannot be null");
        // L'identifiant promet ML-DSA-65 : tout autre jeu de paramètres est refusé dès la construction
        if (!KemKeyWrap.hasParameterSet(keys.getPublic(), PARAMETER_SET)) {
            throw new InvalidKeyException(ID + " requires an " + PARAMETER_SET + " key");
        }
        this.keys = keys;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(keys.getPrivate());
        signer.update(data);
        return signer.sign();
    }

    @Override
    public boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(keys.getPublic());
        verifier.update(data);
        try {
            return verifier.verify(signature);
        } catch (SignatureException e) {
            return false;
        }
    }
}