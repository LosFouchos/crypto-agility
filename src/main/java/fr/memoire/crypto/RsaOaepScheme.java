package fr.memoire.crypto;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

// Adapte RsaOaep (inchangé) à l'interface KeyProtectionScheme
public final class RsaOaepScheme implements KeyProtectionScheme {

    public static final String ID = "RSA-OAEP-3072-SHA256";
    private static final int KEY_SIZE_BITS = 3072;

    private final KeyPair keys;

    public RsaOaepScheme(KeyPair keys) throws InvalidKeyException {
        Objects.requireNonNull(keys, "Keys cannot be null");
        // L'identifiant promet 3072 bits : toute autre clé est refusée dès la construction
        if (!(keys.getPublic() instanceof RSAPublicKey publicKey)
                || publicKey.getModulus().bitLength() != KEY_SIZE_BITS) {
            throw new InvalidKeyException(ID + " requires an RSA key of " + KEY_SIZE_BITS + " bits");
        }
        this.keys = keys;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public byte[] protect(SecretKey dataKey) throws GeneralSecurityException {
        return RsaOaep.wrapKey(keys.getPublic(), dataKey);
    }

    @Override
    public SecretKey unprotect(byte[] protectedKey) throws GeneralSecurityException {
        return RsaOaep.unwrapKey(keys.getPrivate(), protectedKey);
    }
}