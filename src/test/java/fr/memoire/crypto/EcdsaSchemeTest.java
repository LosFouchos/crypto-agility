package fr.memoire.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class EcdsaSchemeTest {

    // La brique signe puis vérifie
    @Test
    void validSignatureIsAccepted() throws GeneralSecurityException {
        SignatureScheme scheme = new EcdsaScheme(EcdsaSignature.generateKeyPair());
        byte[] data = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

        assertTrue(scheme.verify(data, scheme.sign(data)));
    }

    // Mauvais paramétrage : une clé sur la courbe P-384 ne correspond pas à l'identifiant
    @Test
    void rejectsKeyOnWrongCurve() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));

        assertThrows(InvalidKeyException.class, () -> new EcdsaScheme(generator.generateKeyPair()));
    }
}