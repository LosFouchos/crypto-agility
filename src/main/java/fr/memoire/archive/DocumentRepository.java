package fr.memoire.archive;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DocumentRepository {

    void save(Document document) throws IOException;
    Optional<Document> findById(UUID id)throws IOException;
    List<Metadata> findByIdClient(String idClient)throws IOException;
}
