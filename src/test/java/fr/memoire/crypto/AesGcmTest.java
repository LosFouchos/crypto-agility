package fr.memoire.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmTest {

    private static final byte[] PLAINTEXT = "Contrat n°42 : 10 000 EUR".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "idClient=CLI-0001".getBytes(StandardCharsets.UTF_8);

    //Chiffrer puis déchiffrer redonne le contenu d'origine
    @Test
    void decryptReturnsOriginalPlaintext() throws GeneralSecurityException {
        SecretKey key = AesGcm.generateKey();

        byte[] encrypted = AesGcm.encrypt(key, PLAINTEXT, AAD);
        byte[] decrypted = AesGcm.decrypt(key, encrypted, AAD);

        assertArrayEquals(PLAINTEXT, decrypted);
    }

    //Modifier un seul bit du texte chiffré fait échouer le déchiffrement
    @Test
    void tamperedCiphertextIsRejected() throws GeneralSecurityException {
        SecretKey key = AesGcm.generateKey();
        byte[] encrypted = AesGcm.encrypt(key, PLAINTEXT, AAD);

        encrypted[15] ^= 1;   // on inverse un seul bit, après le nonce

        assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, encrypted, AAD));
    }

    //Modifier les données associées fait échouer le déchiffrement
    @Test
    void modifiedAadIsRejected() throws GeneralSecurityException {
        SecretKey key = AesGcm.generateKey();
        byte[] encrypted = AesGcm.encrypt(key, PLAINTEXT, AAD);

        byte[] forgedAad = "idClient=CLI-9999".getBytes(StandardCharsets.UTF_8);

        assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, encrypted, forgedAad));
    }

    //Deux chiffrements du même contenu donnent deux résultats différents
    @Test
    void sameInputGivesDifferentCiphertexts() throws GeneralSecurityException {
        SecretKey key = AesGcm.generateKey();

        byte[] encrypted1 = AesGcm.encrypt(key, PLAINTEXT, AAD);
        byte[] encrypted2 = AesGcm.encrypt(key, PLAINTEXT, AAD);

        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    //Le format : nonce (12) + contenu + étiquette (16)
    @Test
    void ciphertextIs28BytesLongerThanPlaintext() throws GeneralSecurityException {
        SecretKey key = AesGcm.generateKey();

        byte[] encrypted = AesGcm.encrypt(key, PLAINTEXT, AAD);

        assertEquals(PLAINTEXT.length + 28, encrypted.length);
    }
}