package fr.memoire.agility;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class CryptoPolicyTest {

    // Politique valide de référence : celle de l'introduction de la couche (RSA et ECDSA)
    private static Properties validPolicy() {
        Properties p = new Properties();
        p.setProperty("write.keyProtection", "RSA-OAEP-3072-SHA256");
        p.setProperty("write.signature", "ECDSA-P256-SHA256");
        p.setProperty("state.RSA-OAEP-3072-SHA256", "ALLOWED");
        p.setProperty("state.ECDSA-P256-SHA256", "ALLOWED");
        p.setProperty("state.LEGACY-V1", "READ_ONLY");
        return p;
    }

    @Test
    void validPolicyIsLoaded() {
        CryptoPolicy policy = CryptoPolicy.from(validPolicy());

        assertEquals("RSA-OAEP-3072-SHA256", policy.writeKeyProtection());
        assertEquals("ECDSA-P256-SHA256", policy.writeSignature());
        assertEquals(AlgorithmState.READ_ONLY, policy.stateOf("LEGACY-V1"));
    }

    // Refus au chargement 1 : algorithme d'écriture absent
    @Test
    void missingWriteAlgorithmIsRejected() {
        Properties p = validPolicy();
        p.remove("write.signature");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // Refus au chargement 2 : écrire avec un algorithme qui n'est pas ALLOWED
    @Test
    void writeAlgorithmNotAllowedIsRejected() {
        Properties p = validPolicy();
        p.setProperty("state.RSA-OAEP-3072-SHA256", "READ_ONLY");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // Refus au chargement 3 : un algorithme de signature déclaré comme protection de clé
    @Test
    void writeAlgorithmOfWrongFamilyIsRejected() {
        Properties p = validPolicy();
        p.setProperty("write.keyProtection", "ECDSA-P256-SHA256");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // Refus au chargement 4 : identifiant inconnu (ici une faute de frappe : SHA265)
    @Test
    void unknownAlgorithmIsRejected() {
        Properties p = validPolicy();
        p.setProperty("state.RSA-OAEP-3072-SHA265", "ALLOWED");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // Refus au chargement 5 : état qui n'est pas ALLOWED, READ_ONLY ou FORBIDDEN
    @Test
    void invalidStateIsRejected() {
        Properties p = validPolicy();
        p.setProperty("state.LEGACY-V1", "MAYBE");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // Une entrée mal nommée (faute de frappe sur la clé) n'est pas ignorée silencieusement
    @Test
    void unknownEntryIsRejected() {
        Properties p = validPolicy();
        p.setProperty("writ.signature", "ECDSA-P256-SHA256");

        assertThrows(InvalidPolicyException.class, () -> CryptoPolicy.from(p));
    }

    // READ_ONLY : lecture acceptée, écriture refusée
    @Test
    void readOnlyAlgorithmCanBeReadButNotWritten() {
        CryptoPolicy policy = CryptoPolicy.from(validPolicy());

        assertDoesNotThrow(() -> policy.requireReadable("LEGACY-V1"));
        assertThrows(AlgorithmRejectedException.class, () -> policy.requireWritable("LEGACY-V1"));
    }

    // FORBIDDEN, ou absent de la politique : lecture refusée (refus par défaut)
    @Test
    void forbiddenOrAbsentAlgorithmCannotBeRead() {
        Properties p = validPolicy();
        p.setProperty("state.LEGACY-V1", "FORBIDDEN");
        CryptoPolicy policy = CryptoPolicy.from(p);

        assertThrows(AlgorithmRejectedException.class, () -> policy.requireReadable("LEGACY-V1"));
        // ML-DSA-65 ne figure pas dans la politique
        assertThrows(AlgorithmRejectedException.class, () -> policy.requireReadable("ML-DSA-65"));
    }
}