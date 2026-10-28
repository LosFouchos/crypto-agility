package fr.memoire.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class MlDsaSchemeTest {

    private static final byte[] DATA = "Contrat n°42".getBytes(StandardCharsets.UTF_8);
    private static KeyPair keys;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
        generator.initialize(NamedParameterSpec.ML_DSA_65);
        keys = generator.generateKeyPair();
    }

    // La brique signe puis vérifie ; la signature fait 3 309 octets (FIPS 204, ML-DSA-65)
    @Test
    void validSignatureIsAcceptedAndIs3309Bytes() throws GeneralSecurityException {
        SignatureScheme scheme = new MlDsaScheme(keys);

        byte[] signature = scheme.sign(DATA);

        assertEquals(3309, signature.length);
        assertTrue(scheme.verify(DATA, signature));
    }

    // Des données modifiées sont refusées
    @Test
    void modifiedDataIsRejected() throws GeneralSecurityException {
        SignatureScheme scheme = new MlDsaScheme(keys);
        byte[] signature = scheme.sign(DATA);

        assertFalse(scheme.verify("Contrat n°43".getBytes(StandardCharsets.UTF_8), signature));
    }

    // Mauvais paramétrage : une clé ML-DSA-44 ne correspond pas à l'identifiant
    @Test
    void rejectsWrongParameterSet() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
        generator.initialize(NamedParameterSpec.ML_DSA_44);

        assertThrows(InvalidKeyException.class, () -> new MlDsaScheme(generator.generateKeyPair()));
    }
}