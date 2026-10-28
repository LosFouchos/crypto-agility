package fr.memoire.service;

import fr.memoire.agility.AgileArchiveCrypto;
import fr.memoire.agility.AlgorithmRejectedException;
import fr.memoire.agility.ArchiveFormat;
import fr.memoire.agility.ArchiveV2;
import fr.memoire.agility.CryptoPolicy;
import fr.memoire.agility.SchemeRegistry;
import fr.memoire.archive.ConfidentialityLevel;
import fr.memoire.archive.DocType;
import fr.memoire.archive.FileSystemDocumentRepository;
import fr.memoire.archive.Metadata;
import fr.memoire.corpus.KeyFiles;
import fr.memoire.crypto.MlDsaScheme;
import fr.memoire.crypto.MlKemScheme;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Étape 2 : migration vers ML-KEM-768 et ML-DSA-65 par la seule politique.
// Travaille sur une copie du corpus v1 et de ses clés, complétées par des clés post-quantiques.
class PostQuantumMigrationTest {

    private static final Path CORPUS = Path.of("corpus-v1");
    private static final byte[] CONTENT = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path tempDir;

    private Path archives;
    private SchemeRegistry registry;
    private List<String[]> manifest;

    @BeforeEach
    void prepare() throws IOException, GeneralSecurityException {
        archives = copyDirectory(CORPUS.resolve("archives"), tempDir.resolve("archives"));
        Path keys = copyDirectory(CORPUS.resolve("keys"), tempDir.resolve("keys"));

        KeyPairGenerator mlKem = KeyPairGenerator.getInstance("ML-KEM");
        mlKem.initialize(NamedParameterSpec.ML_KEM_768);
        KeyFiles.save(mlKem.generateKeyPair(), keys, "mlkem");
        KeyPairGenerator mlDsa = KeyPairGenerator.getInstance("ML-DSA");
        mlDsa.initialize(NamedParameterSpec.ML_DSA_65);
        KeyFiles.save(mlDsa.generateKeyPair(), keys, "mldsa");

        registry = SchemeRegistry.load(keys);
        // idDocument;docType;confidentialityLevel;idClient;content
        manifest = Files.readAllLines(CORPUS.resolve("manifest.csv"), StandardCharsets.UTF_8)
                .stream().skip(1).map(line -> line.split(";", 5)).toList();
    }

    private static Path copyDirectory(Path source, Path target) throws IOException {
        Files.createDirectories(target);
        try (DirectoryStream<Path> files = Files.newDirectoryStream(source)) {
            for (Path file : files) {
                Files.copy(file, target.resolve(file.getFileName()));
            }
        }
        return target;
    }

    private ArchiveService service(String writeKeyProtection, String writeSignature,
                                   String classicalState, String legacyState) throws IOException {
        Properties p = new Properties();
        p.setProperty("write.keyProtection", writeKeyProtection);
        p.setProperty("write.signature", writeSignature);
        p.setProperty("state." + MlKemScheme.ID, "ALLOWED");
        p.setProperty("state." + MlDsaScheme.ID, "ALLOWED");
        // Avant la migration, les algorithmes classiques servent à écrire : ils doivent être ALLOWED
        p.setProperty("state.RSA-OAEP-3072-SHA256",
                writeKeyProtection.startsWith("RSA") ? "ALLOWED" : classicalState);
        p.setProperty("state.ECDSA-P256-SHA256",
                writeSignature.startsWith("ECDSA") ? "ALLOWED" : classicalState);
        p.setProperty("state.LEGACY-V1", legacyState);
        return new ArchiveService(new FileSystemDocumentRepository(archives),
                new AgileArchiveCrypto(CryptoPolicy.from(p), registry));
    }

    private ArchiveService beforeMigration() throws IOException {
        return service("RSA-OAEP-3072-SHA256", "ECDSA-P256-SHA256", "ALLOWED", "READ_ONLY");
    }

    private ArchiveService afterMigration() throws IOException {
        return service(MlKemScheme.ID, MlDsaScheme.ID, "READ_ONLY", "READ_ONLY");
    }

    private Metadata deposit(ArchiveService service) throws GeneralSecurityException, IOException {
        Metadata metadata = new Metadata(UUID.randomUUID(), ConfidentialityLevel.SECRET,
                DocType.CONTRAT, "CLI-0100", Instant.now(), Period.ofYears(10));
        service.deposit(metadata, CONTENT);
        return metadata;
    }

    private ArchiveV2 storedArchive(UUID id) throws IOException, GeneralSecurityException {
        return ArchiveFormat.read(Files.readAllBytes(archives.resolve(id + ".bin")));
    }

    // Après la migration, les nouveaux dépôts sont protégés par ML-KEM-768 et signés par ML-DSA-65
    @Test
    void newArchivesArePostQuantum() throws GeneralSecurityException, IOException {
        ArchiveService service = afterMigration();
        Metadata metadata = deposit(service);

        ArchiveV2 archive = storedArchive(metadata.idDocument());

        assertEquals(MlKemScheme.ID, archive.keyProtectionId());
        assertEquals(MlDsaScheme.ID, archive.signatureId());
        assertArrayEquals(CONTENT, service.consult(metadata.idDocument()).orElseThrow().content());
    }

    // E4 : après la migration, les archives v1 du corpus et les archives v2 classiques restent lisibles
    @Test
    void archivesFromBeforeMigrationStayReadable() throws GeneralSecurityException, IOException {
        Metadata classical = deposit(beforeMigration());
        ArchiveService service = afterMigration();

        assertArrayEquals(CONTENT, service.consult(classical.idDocument()).orElseThrow().content());
        for (String[] entry : manifest) {
            byte[] content = service.consult(UUID.fromString(entry[0])).orElseThrow().content();
            assertEquals(entry[4], new String(content, StandardCharsets.UTF_8));
        }
    }

    // Rétrogradation : une archive ML-KEM dont l'identifiant annonce RSA, interdit, est refusée
    @Test
    void downgradeToForbiddenAlgorithmIsRejected() throws GeneralSecurityException, IOException {
        Metadata metadata = deposit(afterMigration());
        ArchiveV2 archive = storedArchive(metadata.idDocument());
        Files.write(archives.resolve(metadata.idDocument() + ".bin"), ArchiveFormat.write(
                archive.withKeyProtection("RSA-OAEP-3072-SHA256", archive.protectedKey())));

        ArchiveService rsaForbidden = service(MlKemScheme.ID, MlDsaScheme.ID, "FORBIDDEN", "READ_ONLY");

        assertThrows(AlgorithmRejectedException.class, () -> rsaForbidden.consult(metadata.idDocument()));
    }

    // Promesse de la 2.2 : remplacer l'enveloppe sans rechiffrer le contenu ni refaire la signature
    @Test
    void envelopeIsReplacedWithoutReencryptingOrResigning() throws GeneralSecurityException, IOException {
        Metadata metadata = deposit(beforeMigration());
        ArchiveV2 before = storedArchive(metadata.idDocument());

        // Politique intermédiaire : seule la protection de clé change
        ArchiveService service = service(MlKemScheme.ID, "ECDSA-P256-SHA256", "READ_ONLY", "READ_ONLY");
        assertTrue(service.reprotect(metadata.idDocument()));
        ArchiveV2 after = storedArchive(metadata.idDocument());

        assertEquals(MlKemScheme.ID, after.keyProtectionId());
        assertArrayEquals(before.encryptedContent(), after.encryptedContent());
        assertArrayEquals(before.signature(), after.signature());
        assertArrayEquals(CONTENT, service.consult(metadata.idDocument()).orElseThrow().content());
    }

    // Migration complète : tout est re-protégé, puis les algorithmes classiques et le format v1 sont interdits
    @Test
    void afterFullReprotectionNoArchiveDependsOnClassicalAlgorithms() throws GeneralSecurityException, IOException {
        Metadata classical = deposit(beforeMigration());
        ArchiveService service = afterMigration();

        for (ArchiveService.InventoryEntry entry : service.inventory()) {
            service.reprotect(entry.idDocument());
        }
        for (ArchiveService.InventoryEntry entry : service.inventory()) {
            assertEquals(MlKemScheme.ID, entry.protection().keyProtectionId());
            assertEquals(MlDsaScheme.ID, entry.protection().signatureId());
        }

        ArchiveService classicalForbidden = service(MlKemScheme.ID, MlDsaScheme.ID, "FORBIDDEN", "FORBIDDEN");
        assertArrayEquals(CONTENT, classicalForbidden.consult(classical.idDocument()).orElseThrow().content());
        for (String[] entry : manifest) {
            byte[] content = classicalForbidden.consult(UUID.fromString(entry[0])).orElseThrow().content();
            assertEquals(entry[4], new String(content, StandardCharsets.UTF_8));
        }
    }
}