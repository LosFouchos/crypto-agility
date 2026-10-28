package fr.memoire.service;

import fr.memoire.agility.AgileArchiveCrypto;
import fr.memoire.agility.ArchiveFormat;
import fr.memoire.agility.ArchiveV2;
import fr.memoire.agility.CryptoPolicy;
import fr.memoire.agility.SchemeRegistry;
import fr.memoire.archive.ConfidentialityLevel;
import fr.memoire.archive.DocType;
import fr.memoire.archive.FileSystemDocumentRepository;
import fr.memoire.archive.Metadata;
import fr.memoire.corpus.KeyFiles;
import fr.memoire.crypto.HybridX25519MlKemScheme;
import fr.memoire.crypto.MlDsaScheme;
import fr.memoire.crypto.MlKemScheme;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.time.Period;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Étape 3 : passage de ML-KEM-768 seul à l'hybride X25519 + ML-KEM-768, par la seule politique
class HybridMigrationTest {

    private static final byte[] CONTENT = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path tempDir;

    private Path archives;
    private SchemeRegistry registry;

    @BeforeEach
    void prepare() throws IOException, GeneralSecurityException {
        archives = Files.createDirectories(tempDir.resolve("archives"));
        Path keys = Files.createDirectories(tempDir.resolve("keys"));
        KeyFiles.save(generate("ML-KEM", NamedParameterSpec.ML_KEM_768), keys, "mlkem");
        KeyFiles.save(generate("ML-DSA", NamedParameterSpec.ML_DSA_65), keys, "mldsa");
        KeyFiles.save(generate("X25519", NamedParameterSpec.X25519), keys, "x25519");
        registry = SchemeRegistry.load(keys);
    }

    private static java.security.KeyPair generate(String algorithm, NamedParameterSpec parameterSet)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(parameterSet);
        return generator.generateKeyPair();
    }

    private ArchiveService service(String writeKeyProtection) throws IOException {
        Properties p = new Properties();
        p.setProperty("write.keyProtection", writeKeyProtection);
        p.setProperty("write.signature", MlDsaScheme.ID);
        p.setProperty("state." + HybridX25519MlKemScheme.ID, "ALLOWED");
        p.setProperty("state." + MlKemScheme.ID,
                writeKeyProtection.equals(MlKemScheme.ID) ? "ALLOWED" : "READ_ONLY");
        p.setProperty("state." + MlDsaScheme.ID, "ALLOWED");
        return new ArchiveService(new FileSystemDocumentRepository(archives),
                new AgileArchiveCrypto(CryptoPolicy.from(p), registry));
    }

    private Metadata deposit(ArchiveService service) throws GeneralSecurityException, IOException {
        Metadata metadata = new Metadata(UUID.randomUUID(), ConfidentialityLevel.SECRET,
                DocType.CONTRAT, "CLI-0200", Instant.now(), Period.ofYears(10));
        service.deposit(metadata, CONTENT);
        return metadata;
    }

    private ArchiveV2 storedArchive(UUID id) throws IOException, GeneralSecurityException {
        return ArchiveFormat.read(Files.readAllBytes(archives.resolve(id + ".bin")));
    }

    // Les nouveaux dépôts sont hybrides ; les archives ML-KEM existantes restent lisibles
    @Test
    void newArchivesAreHybridAndOldOnesStayReadable() throws GeneralSecurityException, IOException {
        Metadata before = deposit(service(MlKemScheme.ID));
        ArchiveService hybrid = service(HybridX25519MlKemScheme.ID);
        Metadata after = deposit(hybrid);

        assertEquals(HybridX25519MlKemScheme.ID, storedArchive(after.idDocument()).keyProtectionId());
        assertArrayEquals(CONTENT, hybrid.consult(after.idDocument()).orElseThrow().content());
        assertArrayEquals(CONTENT, hybrid.consult(before.idDocument()).orElseThrow().content());
    }

    // Le passage à l'hybride ne remplace que l'enveloppe : contenu chiffré et signature inchangés
    @Test
    void envelopeIsReplacedByHybridWithoutReencrypting() throws GeneralSecurityException, IOException {
        Metadata metadata = deposit(service(MlKemScheme.ID));
        ArchiveV2 before = storedArchive(metadata.idDocument());

        ArchiveService hybrid = service(HybridX25519MlKemScheme.ID);
        assertTrue(hybrid.reprotect(metadata.idDocument()));
        ArchiveV2 after = storedArchive(metadata.idDocument());

        assertEquals(HybridX25519MlKemScheme.ID, after.keyProtectionId());
        assertArrayEquals(before.encryptedContent(), after.encryptedContent());
        assertArrayEquals(before.signature(), after.signature());
        assertArrayEquals(CONTENT, hybrid.consult(metadata.idDocument()).orElseThrow().content());
    }
}