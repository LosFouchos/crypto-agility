package fr.memoire.service;

import fr.memoire.archive.ConfidentialityLevel;
import fr.memoire.archive.DocType;
import fr.memoire.archive.FileSystemDocumentRepository;
import fr.memoire.archive.Metadata;
import fr.memoire.crypto.AesGcm;
import fr.memoire.crypto.EcdsaSignature;
import fr.memoire.crypto.RsaOaep;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.time.Instant;
import java.time.Period;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ArchiveServiceTest {

    private static final byte[] CONTENT = "Contrat n°42".getBytes(StandardCharsets.UTF_8);

    // Clés générées une seule fois
    private static KeyPair rsaKeys;
    private static KeyPair ecdsaKeys;

    @TempDir
    Path tempDir;

    private ArchiveService service;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        rsaKeys = RsaOaep.generateKeyPair();
        ecdsaKeys = EcdsaSignature.generateKeyPair();
    }

    @BeforeEach
    void setUp() throws IOException {
        service = new ArchiveService(new FileSystemDocumentRepository(tempDir), rsaKeys, ecdsaKeys);
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

    // Inverse un bit du fichier .bin
    private void flipBit(UUID id, int position) throws IOException {
        Path file = tempDir.resolve(id + ".bin");
        byte[] bytes = Files.readAllBytes(file);
        bytes[position] ^= 1;
        Files.write(file, bytes);
    }

    // Le circuit complet : déposer puis consulter rend le contenu d'origine
    @Test
    void depositThenConsultReturnsOriginalContent() throws GeneralSecurityException, IOException {
        Metadata metadata = depositSample();

        var document = service.consult(metadata.idDocument()).orElseThrow();

        assertEquals(metadata, document.metadata());
        assertArrayEquals(CONTENT, document.content());
    }

    // Un bit modifié dans l'enveloppe RSA empêche d'ouvrir l'archive
    @Test
    void tamperedEnvelopeIsRejected() throws GeneralSecurityException, IOException {
        UUID id = depositSample().idDocument();

        flipBit(id, 10);

        assertThrows(GeneralSecurityException.class, () -> service.consult(id));
    }

    // Un bit modifié dans le contenu chiffré est détecté par AES-GCM
    @Test
    void tamperedEncryptedContentIsRejected() throws GeneralSecurityException, IOException {
        UUID id = depositSample().idDocument();
        int lastByte = (int) Files.size(tempDir.resolve(id + ".bin")) - 1;

        flipBit(id, lastByte);

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
        Path file = tempDir.resolve(metadata.idDocument() + ".bin");
        byte[] original = Files.readAllBytes(file);

        // L'attaquant chiffre un faux contenu avec sa propre clé AES
        SecretKey forgedKey = AesGcm.generateKey();
        byte[] forgedContent = AesGcm.encrypt(forgedKey,
                "Faux contrat".getBytes(StandardCharsets.UTF_8), metadata.toBytes());
        byte[] forgedEnvelope = RsaOaep.wrapKey(rsaKeys.getPublic(), forgedKey);

        // Il recopie la longueur et l'ancienne signature, situées juste après l'enveloppe
        int signatureLength = ((original[384] & 0xFF) << 8) | (original[385] & 0xFF);
        byte[] oldSignaturePart = Arrays.copyOfRange(original, 384, 386 + signatureLength);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(forgedEnvelope);
            out.write(oldSignaturePart);
            out.write(forgedContent);
        }
        Files.write(file, buffer.toByteArray());

        assertThrows(SignatureException.class, () -> service.consult(metadata.idDocument()));
    }
}