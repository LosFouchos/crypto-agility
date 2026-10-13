package fr.memoire.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class RsaOaepTest {

    private static KeyPair keyPair;

    // Exécuté une seule fois avant tous les tests : la génération RSA est lente
    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        keyPair = RsaOaep.generateKeyPair();
    }

    //Ouvrir l'enveloppe redonne la même clé AES
    @Test
    void unwrapReturnsOriginalKey() throws GeneralSecurityException {
        SecretKey aesKey = AesGcm.generateKey();

        byte[] wrapped = RsaOaep.wrapKey(keyPair.getPublic(), aesKey);
        SecretKey unwrapped = RsaOaep.unwrapKey(keyPair.getPrivate(), wrapped);

        assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }

    //L'enveloppe fait la taille de la clé RSA : 3072 bits = 384 octets
    @Test
    void wrappedKeyIs384Bytes() throws GeneralSecurityException {
        byte[] wrapped = RsaOaep.wrapKey(keyPair.getPublic(), AesGcm.generateKey());

        assertEquals(384, wrapped.length);
    }

    //Une autre clé privée ne peut pas ouvrir l'enveloppe
    @Test
    void wrongPrivateKeyIsRejected() throws GeneralSecurityException {
        byte[] wrapped = RsaOaep.wrapKey(keyPair.getPublic(), AesGcm.generateKey());
        KeyPair otherKeyPair = RsaOaep.generateKeyPair();

        assertThrows(GeneralSecurityException.class,
                () -> RsaOaep.unwrapKey(otherKeyPair.getPrivate(), wrapped));
    }

    //OAEP est probabiliste : la même clé donne deux enveloppes différentes
    @Test
    void sameKeyGivesDifferentEnvelopes() throws GeneralSecurityException {
        SecretKey aesKey = AesGcm.generateKey();

        byte[] wrapped1 = RsaOaep.wrapKey(keyPair.getPublic(), aesKey);
        byte[] wrapped2 = RsaOaep.wrapKey(keyPair.getPublic(), aesKey);

        assertFalse(Arrays.equals(wrapped1, wrapped2));
    }
}