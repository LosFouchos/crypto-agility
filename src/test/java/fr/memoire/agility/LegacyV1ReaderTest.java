package fr.memoire.agility;

import fr.memoire.archive.Document;
import fr.memoire.archive.FileSystemDocumentRepository;
import fr.memoire.corpus.KeyFiles;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Ces tests lisent le vrai corpus v1, produit par la version de référence (dossier corpus-v1)
class LegacyV1ReaderTest {

    private static final Path CORPUS = Path.of("corpus-v1");

    private static LegacyV1Reader reader;
    private static FileSystemDocumentRepository archives;
    private static List<String[]> manifest;

    @BeforeAll
    static void loadCorpus() throws IOException, GeneralSecurityException {
        Path keys = CORPUS.resolve("keys");
        reader = new LegacyV1Reader(KeyFiles.load(keys, "rsa", "RSA"), KeyFiles.load(keys, "ecdsa", "EC"));
        archives = new FileSystemDocumentRepository(CORPUS.resolve("archives"));
        // Lignes du manifeste, sans l'en-tête : idDocument;docType;confidentialityLevel;idClient;content
        manifest = Files.readAllLines(CORPUS.resolve("manifest.csv"), StandardCharsets.UTF_8)
                .stream().skip(1).map(line -> line.split(";", 5)).toList();
    }

    private static Document stored(String id) throws IOException {
        return archives.findById(UUID.fromString(id)).orElseThrow();
    }

    // Vérification unique du corpus : aucune archive v1 ne commence par la marque CAG2,
    // donc aucune ne peut être confondue avec une archive v2
    @Test
    void noCorpusArchiveLooksLikeV2() throws IOException {
        assertEquals(9, manifest.size());
        for (String[] entry : manifest) {
            assertFalse(ArchiveFormat.isV2(stored(entry[0]).content()));
        }
    }

    // Les 9 archives du corpus sont relues, vérifiées, et leur contenu correspond au manifeste
    @Test
    void allCorpusArchivesAreReadAndVerified() throws IOException, GeneralSecurityException {
        for (String[] entry : manifest) {
            Document document = stored(entry[0]);

            byte[] content = reader.open(document.metadata().toBytes(), document.content());

            assertEquals(entry[4], new String(content, StandardCharsets.UTF_8));
        }
    }

    // Une archive v1 dont la signature est altérée est refusée
    @Test
    void tamperedSignatureIsRejected() throws IOException {
        Document document = stored(manifest.get(0)[0]);
        byte[] data = document.content();
        data[390] ^= 1; // octet situé dans la signature (après 384 + 2 octets)

        assertThrows(SignatureException.class,
                () -> reader.open(document.metadata().toBytes(), data));
    }
}