package fr.memoire.service;

import fr.memoire.agility.ArchiveCrypto;
import fr.memoire.agility.ProtectionInfo;
import fr.memoire.archive.Document;
import fr.memoire.archive.DocumentRepository;
import fr.memoire.archive.Metadata;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

// Service d'archivage. Il ne connaît plus aucun algorithme : toute la cryptographie passe par la couche
public class ArchiveService {

    private final DocumentRepository repository;
    private final ArchiveCrypto crypto;

    public ArchiveService(DocumentRepository repository, ArchiveCrypto crypto) {
        this.repository = Objects.requireNonNull(repository, "Repository can't be null");
        this.crypto = Objects.requireNonNull(crypto, "Crypto cannot be null");
    }

    public void deposit(Metadata metadata, byte[] content)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(metadata, "Metadata cannot be null");
        Objects.requireNonNull(content, "Content cannot be null");

        byte[] archive = crypto.seal(metadata.toBytes(), content);
        repository.save(new Document(metadata, archive));
    }

    public Optional<Document> consult(UUID id) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(id, "Id cannot be null");

        Optional<Document> stored = repository.findById(id);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        Metadata metadata = stored.get().metadata();
        byte[] content = crypto.open(metadata.toBytes(), stored.get().content());
        return Optional.of(new Document(metadata, content));
    }

    public List<Metadata> listByClient(String idClient) throws IOException {
        return repository.findByIdClient(idClient);
    }

    // Inventaire (E5) : comment chaque archive est protégée, lu sans aucune clé
    public List<InventoryEntry> inventory() throws GeneralSecurityException, IOException {
        List<InventoryEntry> entries = new ArrayList<>();
        for (UUID id : repository.findAllIds()) {
            Document stored = repository.findById(id).orElseThrow();
            entries.add(new InventoryEntry(id, crypto.describe(stored.content())));
        }
        return entries;
    }

    // Re-protège une archive avec les algorithmes d'écriture actuels ; renvoie false s'il n'y avait rien à faire
    public boolean reprotect(UUID id) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(id, "Id cannot be null");

        Document stored = repository.findById(id).orElseThrow();
        Optional<byte[]> reprotected = crypto.reprotect(stored.metadata().toBytes(), stored.content());
        if (reprotected.isEmpty()) {
            return false;
        }
        repository.replaceContent(id, reprotected.get());
        return true;
    }

    public record InventoryEntry(UUID idDocument, ProtectionInfo protection) {
    }
}