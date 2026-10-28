package fr.memoire.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class RsaOaepSchemeTest {

    // La brique protège puis rouvre la clé AES
    @Test
    void unprotectReturnsOriginalKey() throws GeneralSecurityException {
        KeyProtectionScheme scheme = new RsaOaepScheme(RsaOaep.generateKeyPair());
        SecretKey dataKey = AesGcm.generateKey();

        SecretKey reopened = scheme.unprotect(scheme.protect(dataKey));

        assertArrayEquals(dataKey.getEncoded(), reopened.getEncoded());
    }

    // Mauvais paramétrage : une clé RSA de 2048 bits ne correspond pas à l'identifiant
    @Test
    void rejectsKeyOfWrongSize() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        assertThrows(InvalidKeyException.class, () -> new RsaOaepScheme(generator.generateKeyPair()));
    }
}