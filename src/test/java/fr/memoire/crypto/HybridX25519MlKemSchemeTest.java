package fr.memoire.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class HybridX25519MlKemSchemeTest {

    private static KeyPair x25519;
    private static KeyPair mlKem;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        x25519 = generate("X25519", NamedParameterSpec.X25519);
        mlKem = generate("ML-KEM", NamedParameterSpec.ML_KEM_768);
    }

    private static KeyPair generate(String algorithm, NamedParameterSpec parameterSet) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(parameterSet);
        return generator.generateKeyPair();
    }

    // La brique protège puis rouvre la clé AES
    @Test
    void unprotectReturnsOriginalKey() throws GeneralSecurityException {
        KeyProtectionScheme scheme = new HybridX25519MlKemScheme(x25519, mlKem);
        SecretKey dataKey = AesGcm.generateKey();

        SecretKey reopened = scheme.unprotect(scheme.protect(dataKey));

        assertArrayEquals(dataKey.getEncoded(), reopened.getEncoded());
    }

    // Taille : 4 + 32 (X25519) + 4 + 1 088 (ML-KEM-768) + 40 (AES Key Wrap)
    @Test
    void protectedKeyIs1168Bytes() throws GeneralSecurityException {
        byte[] protectedKey = new HybridX25519MlKemScheme(x25519, mlKem).protect(AesGcm.generateKey());

        assertEquals(1168, protectedKey.length);
    }

    // E4 : une archive hybride ne s'ouvre qu'avec ses DEUX composantes.
    // Avec la bonne clé X25519 mais une autre clé ML-KEM (ou l'inverse), l'ouverture échoue.
    @Test
    void bothComponentsAreRequired() throws GeneralSecurityException {
        byte[] protectedKey = new HybridX25519MlKemScheme(x25519, mlKem).protect(AesGcm.generateKey());

        KeyPair otherMlKem = generate("ML-KEM", NamedParameterSpec.ML_KEM_768);
        KeyPair otherX25519 = generate("X25519", NamedParameterSpec.X25519);
        KeyProtectionScheme wrongPostQuantum = new HybridX25519MlKemScheme(x25519, otherMlKem);
        KeyProtectionScheme wrongClassical = new HybridX25519MlKemScheme(otherX25519, mlKem);

        assertThrows(GeneralSecurityException.class, () -> wrongPostQuantum.unprotect(protectedKey));
        assertThrows(GeneralSecurityException.class, () -> wrongClassical.unprotect(protectedKey));
    }

    // Mauvais paramétrage : les deux clés inversées ne correspondent pas à l'identifiant
    @Test
    void rejectsKeysInWrongOrder() {
        assertThrows(InvalidKeyException.class, () -> new HybridX25519MlKemScheme(mlKem, x25519));
    }
}