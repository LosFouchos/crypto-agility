package fr.memoire.agility;

import fr.memoire.archive.Document;
import fr.memoire.archive.FileSystemDocumentRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// La couche est testée avec les clés du corpus v1, pour pouvoir aussi relire les archives historiques
class AgileArchiveCryptoTest {

    private static final Path CORPUS = Path.of("corpus-v1");
    private static final byte[] METADATA = "metadonnees".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTENT = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

    private static SchemeRegistry registry;
    private static Document corpusDocument;
    private static String corpusContent;

    @BeforeAll
    static void loadKeysAndCorpus() throws IOException, GeneralSecurityException {
        registry = SchemeRegistry.load(CORPUS.resolve("keys"));
        String[] firstEntry = Files.readAllLines(CORPUS.resolve("manifest.csv"), StandardCharsets.UTF_8)
                .get(1).split(";", 5);
        corpusDocument = new FileSystemDocumentRepository(CORPUS.resolve("archives"))
                .findById(UUID.fromString(firstEntry[0])).orElseThrow();
        corpusContent = firstEntry[4];
    }

    private static Properties policy(String legacyState) {
        Properties p = new Properties();
        p.setProperty("write.keyProtection", "RSA-OAEP-3072-SHA256");
        p.setProperty("write.signature", "ECDSA-P256-SHA256");
        p.setProperty("state.RSA-OAEP-3072-SHA256", "ALLOWED");
        p.setProperty("state.ECDSA-P256-SHA256", "ALLOWED");
        p.setProperty("state.LEGACY-V1", legacyState);
        return p;
    }

    private static ArchiveCrypto layer(String legacyState) {
        return new AgileArchiveCrypto(CryptoPolicy.from(policy(legacyState)), registry);
    }

    // Le circuit complet à travers la couche
    @Test
    void sealThenOpenReturnsContent() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");

        byte[] archive = crypto.seal(METADATA, CONTENT);

        assertArrayEquals(CONTENT, crypto.open(METADATA, archive));
    }

    // E2 : l'archive décrit elle-même ses algorithmes, lisibles sans aucune clé
    @Test
    void archiveDescribesItsAlgorithms() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");

        ProtectionInfo info = crypto.describe(crypto.seal(METADATA, CONTENT));

        assertEquals("CAG2", info.format());
        assertEquals("RSA-OAEP-3072-SHA256", info.keyProtectionId());
        assertEquals("ECDSA-P256-SHA256", info.signatureId());
        assertEquals("AES-256-GCM", info.contentCipherId());
    }

    // E4 : une archive du corpus v1 est relue à travers la couche
    @Test
    void legacyArchiveIsReadThroughTheLayer() throws GeneralSecurityException {
        byte[] content = layer("READ_ONLY").open(corpusDocument.metadata().toBytes(), corpusDocument.content());

        assertEquals(corpusContent, new String(content, StandardCharsets.UTF_8));
    }

    // E3 : LEGACY-V1 interdit par la politique, l'archive historique est refusée
    @Test
    void legacyArchiveIsRejectedWhenForbidden() {
        ArchiveCrypto crypto = layer("FORBIDDEN");

        assertThrows(AlgorithmRejectedException.class,
                () -> crypto.open(corpusDocument.metadata().toBytes(), corpusDocument.content()));
    }

    // Mauvais paramétrage : une archive qui annonce un algorithme inconnu de la politique est refusée
    // avant toute opération cryptographique
    @Test
    void archiveWithUnknownAlgorithmIsRejected() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");
        ArchiveV2 parsed = ArchiveFormat.read(crypto.seal(METADATA, CONTENT));
        byte[] tampered = ArchiveFormat.write(
                parsed.withKeyProtection("RSA-OAEP-1024-SHA1", parsed.protectedKey()));

        assertThrows(AlgorithmRejectedException.class, () -> crypto.open(METADATA, tampered));
    }

    // Des métadonnées modifiées font échouer l'ouverture (données associées)
    @Test
    void modifiedMetadataIsRejected() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");
        byte[] archive = crypto.seal(METADATA, CONTENT);

        assertThrows(GeneralSecurityException.class,
                () -> crypto.open("autres metadonnees".getBytes(StandardCharsets.UTF_8), archive));
    }

    // Re-protection : une archive v1 devient une archive v2 lisible, au contenu identique
    @Test
    void legacyArchiveIsReprotectedAsV2() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");
        byte[] metadataBytes = corpusDocument.metadata().toBytes();

        byte[] reprotected = crypto.reprotect(metadataBytes, corpusDocument.content()).orElseThrow();

        assertTrue(ArchiveFormat.isV2(reprotected));
        assertEquals(corpusContent, new String(crypto.open(metadataBytes, reprotected), StandardCharsets.UTF_8));
    }

    // Re-protection : rien à faire pour une archive déjà protégée par les algorithmes d'écriture
    @Test
    void currentArchiveNeedsNoReprotection() throws GeneralSecurityException {
        ArchiveCrypto crypto = layer("READ_ONLY");

        assertTrue(crypto.reprotect(METADATA, crypto.seal(METADATA, CONTENT)).isEmpty());
    }
}