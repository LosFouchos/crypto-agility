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

class MlKemSchemeTest {

    private static KeyPair keys;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM");
        generator.initialize(NamedParameterSpec.ML_KEM_768);
        keys = generator.generateKeyPair();
    }

    // La brique protège puis rouvre la clé AES
    @Test
    void unprotectReturnsOriginalKey() throws GeneralSecurityException {
        KeyProtectionScheme scheme = new MlKemScheme(keys);
        SecretKey dataKey = AesGcm.generateKey();

        SecretKey reopened = scheme.unprotect(scheme.protect(dataKey));

        assertArrayEquals(dataKey.getEncoded(), reopened.getEncoded());
    }

    // Taille de la clé protégée : 4 (longueur) + 1 088 (encapsulation ML-KEM-768) + 40 (AES Key Wrap)
    @Test
    void protectedKeyIs1132Bytes() throws GeneralSecurityException {
        byte[] protectedKey = new MlKemScheme(keys).protect(AesGcm.generateKey());

        assertEquals(1132, protectedKey.length);
    }

    // Rejet implicite : ML-KEM ne signale pas une encapsulation altérée,
    // mais l'ouverture par AES Key Wrap échoue
    @Test
    void tamperedEncapsulationIsRejected() throws GeneralSecurityException {
        KeyProtectionScheme scheme = new MlKemScheme(keys);
        byte[] protectedKey = scheme.protect(AesGcm.generateKey());
        protectedKey[10] ^= 1; // octet situé dans l'encapsulation

        assertThrows(GeneralSecurityException.class, () -> scheme.unprotect(protectedKey));
    }

    // Mauvais paramétrage : une clé ML-KEM-512 ne correspond pas à l'identifiant
    @Test
    void rejectsWrongParameterSet() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM");
        generator.initialize(NamedParameterSpec.ML_KEM_512);

        assertThrows(InvalidKeyException.class, () -> new MlKemScheme(generator.generateKeyPair()));
    }
}