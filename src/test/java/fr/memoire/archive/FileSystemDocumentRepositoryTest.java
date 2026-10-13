package fr.memoire.archive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemDocumentRepositoryTest {

    @TempDir
    Path tempDir;

    private DocumentRepository repository;

    @BeforeEach
    void setUp() throws IOException {
        repository = new FileSystemDocumentRepository(tempDir);
    }

    // Fabrique des métadonnées valides pour un client donné
    private static Metadata metadataFor(String idClient) {
        return new Metadata(UUID.randomUUID(), ConfidentialityLevel.CONFIDENTIEL,
                DocType.CONTRAT, idClient, Instant.now(), Period.ofYears(10));
    }

    // Fabrique un document avec un petit contenu
    private static Document documentFor(String idClient) {
        return new Document(metadataFor(idClient), "contenu".getBytes(StandardCharsets.UTF_8));
    }

    // Le test d'aller-retour : enregistrer puis relire donne le même document
    @Test
    void savedDocumentCanBeReadBackIdentical() throws IOException {
        Document original = new Document(metadataFor("CLI-0001"),
                "Contrat n°42".getBytes(StandardCharsets.UTF_8));

        repository.save(original);
        Optional<Document> reread = repository.findById(original.metadata().idDocument());

        assertTrue(reread.isPresent());
        assertEquals(original, reread.get());
    }

    // Un identifiant inconnu donne une boîte vide, pas une erreur
    @Test
    void unknownIdReturnsEmpty() throws IOException {
        Optional<Document> result = repository.findById(UUID.randomUUID());

        assertTrue(result.isEmpty());
    }

    // La recherche par client ne renvoie que les documents de ce client
    @Test
    void findByIdClientReturnsOnlyThatClientsDocuments() throws IOException {
        repository.save(documentFor("CLI-A"));
        repository.save(documentFor("CLI-A"));
        repository.save(documentFor("CLI-B"));

        List<Metadata> result = repository.findByIdClient("CLI-A");

        assertEquals(2, result.size());
        for (Metadata metadata : result) {
            assertEquals("CLI-A", metadata.idClient());
        }
    }

    // Un client sans document donne une liste vide, pas une erreur
    @Test
    void unknownClientReturnsEmptyList() throws IOException {
        repository.save(documentFor("CLI-A"));

        List<Metadata> result = repository.findByIdClient("CLI-INCONNU");

        assertTrue(result.isEmpty());
    }
}