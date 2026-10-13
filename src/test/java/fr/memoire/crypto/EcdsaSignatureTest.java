package fr.memoire.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class EcdsaSignatureTest {

    private static final byte[] DATA = "Contrat n°42 : 10 000 EUR".getBytes(StandardCharsets.UTF_8);
    private static KeyPair keyPair;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        keyPair = EcdsaSignature.generateKeyPair();
    }

    //Une signature authentique est acceptée
    @Test
    void validSignatureIsAccepted() throws GeneralSecurityException {
        byte[] signature = EcdsaSignature.sign(keyPair.getPrivate(), DATA);

        assertTrue(EcdsaSignature.verify(keyPair.getPublic(), DATA, signature));
    }

    //Des données modifiées sont détectées
    @Test
    void modifiedDataIsRejected() throws GeneralSecurityException {
        byte[] signature = EcdsaSignature.sign(keyPair.getPrivate(), DATA);
        byte[] forged = "Contrat n°42 : 90 000 EUR".getBytes(StandardCharsets.UTF_8);

        assertFalse(EcdsaSignature.verify(keyPair.getPublic(), forged, signature));
    }

    //Une signature produite par une autre clé est refusée
    @Test
    void signatureFromAnotherKeyIsRejected() throws GeneralSecurityException {
        KeyPair attackerKeyPair = EcdsaSignature.generateKeyPair();
        byte[] signature = EcdsaSignature.sign(attackerKeyPair.getPrivate(), DATA);

        assertFalse(EcdsaSignature.verify(keyPair.getPublic(), DATA, signature));
    }

    //Une signature corrompue est refusée, sans exception
    @Test
    void corruptedSignatureIsRejected() throws GeneralSecurityException {
        byte[] signature = EcdsaSignature.sign(keyPair.getPrivate(), DATA);
        signature[10] ^= 1;

        assertFalse(EcdsaSignature.verify(keyPair.getPublic(), DATA, signature));
    }
}