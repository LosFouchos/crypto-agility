package fr.memoire.service;

import fr.memoire.agility.AgileArchiveCrypto;
import fr.memoire.agility.AlgorithmRejectedException;
import fr.memoire.agility.CryptoPolicy;
import fr.memoire.agility.SchemeRegistry;
import fr.memoire.archive.FileSystemDocumentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Le corpus v1 traverse la couche de bout en bout, sur une COPIE (le vrai corpus n'est jamais modifié)
class CorpusMigrationTest {

    private static final Path CORPUS = Path.of("corpus-v1");

    @TempDir
    Path tempDir;

    private Path archives;
    private List<String[]> manifest;

    @BeforeEach
    void copyCorpus() throws IOException {
        archives = tempDir.resolve("archives");
        Files.createDirectories(archives);
        try (DirectoryStream<Path> files = Files.newDirectoryStream(CORPUS.resolve("archives"))) {
            for (Path file : files) {
                Files.copy(file, archives.resolve(file.getFileName()));
            }
        }
        // idDocument;docType;confidentialityLevel;idClient;content
        manifest = Files.readAllLines(CORPUS.resolve("manifest.csv"), StandardCharsets.UTF_8)
                .stream().skip(1).map(line -> line.split(";", 5)).toList();
    }

    private ArchiveService serviceWithLegacy(String legacyState) throws IOException, GeneralSecurityException {
        Properties p = new Properties();
        p.setProperty("write.keyProtection", "RSA-OAEP-3072-SHA256");
        p.setProperty("write.signature", "ECDSA-P256-SHA256");
        p.setProperty("state.RSA-OAEP-3072-SHA256", "ALLOWED");
        p.setProperty("state.ECDSA-P256-SHA256", "ALLOWED");
        p.setProperty("state.LEGACY-V1", legacyState);
        return new ArchiveService(new FileSystemDocumentRepository(archives),
                new AgileArchiveCrypto(CryptoPolicy.from(p), SchemeRegistry.load(CORPUS.resolve("keys"))));
    }

    private void assertWholeCorpusReadable(ArchiveService service) throws GeneralSecurityException, IOException {
        for (String[] entry : manifest) {
            byte[] content = service.consult(UUID.fromString(entry[0])).orElseThrow().content();
            assertEquals(entry[4], new String(content, StandardCharsets.UTF_8));
        }
    }

    private long countFormat(ArchiveService service, String format) throws GeneralSecurityException, IOException {
        return service.inventory().stream().filter(e -> e.protection().format().equals(format)).count();
    }

    // E4 : les 9 archives v1 sont relues et vérifiées par le service à travers la couche
    @Test
    void corpusIsReadableThroughTheService() throws GeneralSecurityException, IOException {
        assertWholeCorpusReadable(serviceWithLegacy("READ_ONLY"));
    }

    // Scénario complet : inventaire, re-protection, puis interdiction du format historique
    @Test
    void corpusIsReprotectedThenLegacyFormatIsForbidden() throws GeneralSecurityException, IOException {
        ArchiveService service = serviceWithLegacy("READ_ONLY");

        // 1. L'inventaire trouve 9 archives au format historique
        assertEquals(9L, countFormat(service, "LEGACY-V1"));

        // 2. Chacune est re-protégée au format v2
        for (String[] entry : manifest) {
            assertTrue(service.reprotect(UUID.fromString(entry[0])));
        }
        assertEquals(9L, countFormat(service, "CAG2"));

        // 3. Le format historique peut alors être interdit : tout reste lisible
        ArchiveService withoutLegacy = serviceWithLegacy("FORBIDDEN");
        assertWholeCorpusReadable(withoutLegacy);

        // 4. Alors qu'une archive v1 non re-protégée serait désormais refusée
        Path untouched = tempDir.resolve("untouched");
        Files.createDirectories(untouched);
        String id = manifest.get(0)[0];
        Files.copy(CORPUS.resolve("archives").resolve(id + ".bin"), untouched.resolve(id + ".bin"));
        Files.copy(CORPUS.resolve("archives").resolve(id + ".properties"), untouched.resolve(id + ".properties"));
        archives = untouched;
        ArchiveService forbiddenOnOldArchive = serviceWithLegacy("FORBIDDEN");
        assertThrows(AlgorithmRejectedException.class,
                () -> forbiddenOnOldArchive.consult(UUID.fromString(id)));
    }
}