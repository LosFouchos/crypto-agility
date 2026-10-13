package fr.memoire.archive;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Period;
import java.util.*;

public class FileSystemDocumentRepository implements DocumentRepository {

    private final Path directory;
    private static final String KEY_ID_DOCUMENT = "idDocument";
    private static final String KEY_CONFIDENTIALITY_LEVEL = "confidentialityLevel";
    private static final String KEY_DOC_TYPE = "docType";
    private static final String KEY_ID_CLIENT = "idClient";
    private static final String KEY_DATE_DEPOT = "dateDepot";
    private static final String KEY_DURATION_CONSERVATION = "durationConservation";

    public FileSystemDocumentRepository(Path directory) throws IOException {
        this.directory = Objects.requireNonNull(directory, "Directory cannot be null");
        Files.createDirectories(directory);
    }


    @Override
    public void save(Document document) throws IOException {
        Metadata metadata = document.metadata();
        UUID id = metadata.idDocument();

        Path contentFile = directory.resolve(id + ".bin");
        Files.write(contentFile, document.content());

        Properties properties = new Properties();
        properties.setProperty(KEY_ID_DOCUMENT, id.toString());
        properties.setProperty(KEY_CONFIDENTIALITY_LEVEL, metadata.confidentialityLevel().name());
        properties.setProperty(KEY_DOC_TYPE, metadata.docType().name());
        properties.setProperty(KEY_ID_CLIENT, metadata.idClient());
        properties.setProperty(KEY_DATE_DEPOT, metadata.dateDepot().toString());
        properties.setProperty(KEY_DURATION_CONSERVATION, metadata.durationConservation().toString());

        Path metadataFile = directory.resolve(id + ".properties");
        try (var writer = Files.newBufferedWriter(metadataFile)) {
            properties.store(writer, null);
        }
    }

    @Override
    public Optional<Document> findById(UUID id) throws IOException {
        Objects.requireNonNull(id, "Id cannot be null");

        Path metadataFile = directory.resolve(id + ".properties");
        if (!Files.exists(metadataFile)) {
            return Optional.empty();
        }

        Metadata metadata = readMetadata(metadataFile);

        Path contentFile = directory.resolve(id + ".bin");
        byte[] content = Files.readAllBytes(contentFile);

        return Optional.of(new Document(metadata, content));
    }

    private Metadata readMetadata(Path metadataFile) throws IOException {
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(metadataFile)) {
            properties.load(reader);
        }


        return new Metadata(
                UUID.fromString(properties.getProperty(KEY_ID_DOCUMENT)),
                ConfidentialityLevel.valueOf(properties.getProperty(KEY_CONFIDENTIALITY_LEVEL)),
                DocType.valueOf(properties.getProperty(KEY_DOC_TYPE)),
                properties.getProperty(KEY_ID_CLIENT),
                Instant.parse(properties.getProperty(KEY_DATE_DEPOT)),
                Period.parse(properties.getProperty(KEY_DURATION_CONSERVATION))
        );
    }

    @Override
    public List<Metadata> findByIdClient(String idClient) throws IOException {
        Objects.requireNonNull(idClient, "IdClient cannot be null");

        List<Metadata> result = new ArrayList<>();

        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*.properties")) {
            for (Path metadataFile : files) {
                Metadata metadata = readMetadata(metadataFile);
                if (metadata.idClient().equals(idClient)) {
                    result.add(metadata);
                }
            }
        }

        return result;
    }
}
