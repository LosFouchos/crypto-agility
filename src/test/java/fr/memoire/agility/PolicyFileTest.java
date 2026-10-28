package fr.memoire.agility;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

// Le fichier de politique réellement utilisé par l'application est valide
class PolicyFileTest {

    @Test
    void policyFileIsValidAndPostQuantum() throws IOException {
        CryptoPolicy policy = CryptoPolicy.load(Path.of("crypto-policy.properties"));

        assertEquals("ML-KEM-768-HKDF-SHA256-AESKW256", policy.writeKeyProtection());
        assertEquals("ML-DSA-65", policy.writeSignature());
        assertEquals(AlgorithmState.READ_ONLY, policy.stateOf("RSA-OAEP-3072-SHA256"));
    }
}