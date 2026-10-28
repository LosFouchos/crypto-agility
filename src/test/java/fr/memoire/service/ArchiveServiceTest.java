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
import fr.memoire.crypto.AesGcm;
import fr.memoire.crypto.EcdsaScheme;
import fr.memoire.crypto.EcdsaSignature;
import fr.memoire.crypto.RsaOaep;
import fr.memoire.crypto.RsaOaepScheme;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ArchiveServiceTest {

    private static final byte[] CONTENT = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

    // Clés générées une seule fois
    private static KeyPair rsaKeys;
    private static KeyPair ecdsaKeys;
    private static CryptoPolicy policy;

    @TempDir
    Path tempDir;

    private ArchiveService service;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        rsaKeys = RsaOaep.generateKeyPair();
        ecdsaKeys = EcdsaSignature.generateKeyPair();
        Properties p = new Properties();
        p.setProperty("write.keyProtection", "RSA-OAEP-3072-SHA256");
        p.setProperty("write.signature", "ECDSA-P256-SHA256");
        p.setProperty("state.RSA-OAEP-3072-SHA256", "ALLOWED");
        p.setProperty("state.ECDSA-P256-SHA256", "ALLOWED");
        policy = CryptoPolicy.from(p);
    }

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException {
        SchemeRegistry registry = new SchemeRegistry(List.of(new RsaOaepScheme(rsaKeys)),
                List.of(new EcdsaScheme(ecdsaKeys)), null);
        service = new ArchiveService(new FileSystemDocumentRepository(tempDir),
                new AgileArchiveCrypto(policy, registry));
    }

    // Fabrique des métadonnées valides pour un client
    private static Metadata metadataFor(String idClient) {
        return new Metadata(UUID.randomUUID(), ConfidentialityLevel.CONFIDENTIEL,
                DocType.CONTRAT, idClient, Instant.now(), Period.ofYears(10));
    }

    // Dépose le document de test et renvoie ses métadonnées
    private Metadata depositSample() throws GeneralSecurityException, IOException {
        Metadata metadata = metadataFor("CLI-0001");
        service.deposit(metadata, CONTENT);
        return metadata;
    }

    private Path binFile(UUID id) {
        return tempDir.resolve(id + ".bin");
    }

    // Le circuit complet : déposer puis consulter rend le contenu d'origine
    @Test
    void depositThenConsultReturnsOriginalContent() throws GeneralSecurityException, IOException {
        Metadata metadata = depositSample();

        var document = service.consult(metadata.idDocument()).orElseThrow();

        assertEquals(metadata, document.metadata());
        assertArrayEquals(CONTENT, document.content());
    }

    // Une clé AES protégée modifiée empêche d'ouvrir l'archive
    @Test
    void tamperedProtectedKeyIsRejected() throws GeneralSecurityException, IOException {
        UUID id = depositSample().idDocument();
        ArchiveV2 archive = ArchiveFormat.read(Files.readAllBytes(binFile(id)));
        byte[] protectedKey = archive.protectedKey();
        protectedKey[10] ^= 1;
        Files.write(binFile(id), ArchiveFormat.write(archive.withKeyProtection(archive.keyProtectionId(), protectedKey)));

        assertThrows(GeneralSecurityException.class, () -> service.consult(id));
    }

    // Un bit modifié dans le contenu chiffré est détecté par AES-GCM
    @Test
    void tamperedEncryptedContentIsRejected() throws GeneralSecurityException, IOException {
        UUID id = depositSample().idDocument();
        byte[] bytes = Files.readAllBytes(binFile(id));
        bytes[bytes.length - 1] ^= 1;
        Files.write(binFile(id), bytes);

        assertThrows(GeneralSecurityException.class, () -> service.consult(id));
    }

    // Des métadonnées modifiées sur le disque font échouer le déchiffrement
    @Test
    void tamperedMetadataIsRejected() throws GeneralSecurityException, IOException {
        UUID id = depositSample().idDocument();
        Path file = tempDir.resolve(id + ".properties");

        String properties = Files.readString(file);
        Files.writeString(file, properties.replace("CLI-0001", "CLI-9999"));

        assertThrows(GeneralSecurityException.class, () -> service.consult(id));
    }

    // Un attaquant refabrique toute l'archive avec la clé PUBLIQUE RSA :
    // AES-GCM ne voit rien, seule la signature l'arrête
    @Test
    void forgedArchiveIsRejectedBySignature() throws GeneralSecurityException, IOException {
        Metadata metadata = depositSample();
        ArchiveV2 original = ArchiveFormat.read(Files.readAllBytes(binFile(metadata.idDocument())));

        // L'attaquant chiffre un faux contenu avec sa propre clé AES, en connaissant le format
        byte[] aad = concat(metadata.toBytes(),
                ArchiveFormat.authenticatedHeader(original.signatureId(), original.contentCipherId()));
        SecretKey forgedKey = AesGcm.generateKey();
        byte[] forgedContent = AesGcm.encrypt(forgedKey, "Faux contrat".getBytes(StandardCharsets.UTF_8), aad);
        byte[] forgedProtectedKey = RsaOaep.wrapKey(rsaKeys.getPublic(), forgedKey);

        // Il garde l'ancienne signature, qu'il ne peut pas refaire sans la clé privée
        ArchiveV2 forged = new ArchiveV2(original.keyProtectionId(), original.signatureId(),
                original.contentCipherId(), forgedProtectedKey, original.signature(), forgedContent);
        Files.write(binFile(metadata.idDocument()), ArchiveFormat.write(forged));

        assertThrows(SignatureException.class, () -> service.consult(metadata.idDocument()));
    }

    // E5 : l'inventaire décrit chaque archive déposée
    @Test
    void inventoryDescribesEachArchive() throws GeneralSecurityException, IOException {
        depositSample();
        depositSample();

        List<ArchiveService.InventoryEntry> inventory = service.inventory();

        assertEquals(2, inventory.size());
        for (ArchiveService.InventoryEntry entry : inventory) {
            assertEquals("RSA-OAEP-3072-SHA256", entry.protection().keyProtectionId());
            assertEquals("ECDSA-P256-SHA256", entry.protection().signatureId());
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.writeBytes(first);
        buffer.writeBytes(second);
        return buffer.toByteArray();
    }
}