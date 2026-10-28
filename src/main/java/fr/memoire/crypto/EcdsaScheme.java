package fr.memoire.crypto;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Objects;

// Adapte EcdsaSignature (inchangé) à l'interface SignatureScheme
public final class EcdsaScheme implements SignatureScheme {

    public static final String ID = "ECDSA-P256-SHA256";

    private final KeyPair keys;

    public EcdsaScheme(KeyPair keys) throws GeneralSecurityException {
        Objects.requireNonNull(keys, "Keys cannot be null");
        // L'identifiant promet la courbe P-256 : toute autre courbe est refusée dès la construction
        if (!(keys.getPublic() instanceof ECPublicKey publicKey) || !isP256(publicKey.getParams())) {
            throw new InvalidKeyException(ID + " requires a key on curve P-256 (secp256r1)");
        }
        this.keys = keys;
    }

    private static boolean isP256(ECParameterSpec params) throws GeneralSecurityException {
        AlgorithmParameters p256 = AlgorithmParameters.getInstance("EC");
        p256.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = p256.getParameterSpec(ECParameterSpec.class);
        return expected.getCurve().equals(params.getCurve())
                && expected.getGenerator().equals(params.getGenerator())
                && expected.getOrder().equals(params.getOrder());
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        return EcdsaSignature.sign(keys.getPrivate(), data);
    }

    @Override
    public boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException {
        return EcdsaSignature.verify(keys.getPublic(), data, signature);
    }
}