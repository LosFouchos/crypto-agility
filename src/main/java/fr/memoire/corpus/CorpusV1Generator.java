package fr.memoire.corpus;

import fr.memoire.archive.ConfidentialityLevel;
import fr.memoire.archive.DocType;
import fr.memoire.archive.FileSystemDocumentRepository;
import fr.memoire.archive.Metadata;
import fr.memoire.crypto.EcdsaSignature;
import fr.memoire.crypto.RsaOaep;
import fr.memoire.service.ArchiveService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

// Produit le corpus d'archives v1
public class CorpusV1Generator {

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Path corpus = Path.of(args.length > 0 ? args[0] : "corpus-v1");
        if (Files.exists(corpus)) {
            throw new IllegalStateException("Le corpus existe déjà : " + corpus.toAbsolutePath());
        }
        Path keys = Files.createDirectories(corpus.resolve("keys"));
        Path archives = corpus.resolve("archives");

        // Générer et enregistrer les clés
        KeyPair rsaKeys = RsaOaep.generateKeyPair();
        KeyPair ecdsaKeys = EcdsaSignature.generateKeyPair();
        KeyFiles.save(rsaKeys, keys, "rsa");
        KeyFiles.save(ecdsaKeys, keys, "ecdsa");

        // Déposer un document par type et par niveau
        ArchiveService service = new ArchiveService(
                new FileSystemDocumentRepository(archives), rsaKeys, ecdsaKeys);
        List<String> manifest = new ArrayList<>();
        manifest.add("idDocument;docType;confidentialityLevel;idClient;content");

        int number = 1;
        for (DocType docType : DocType.values()) {
            for (ConfidentialityLevel level : ConfidentialityLevel.values()) {
                String idClient = String.format("CLI-%04d", number);
                String content = "Document de test n°" + number + " : " + docType.name()
                        + ", " + level.name();
                Metadata metadata = new Metadata(UUID.randomUUID(), level, docType, idClient,
                        Instant.now(), Period.ofYears(10));

                service.deposit(metadata, content.getBytes(StandardCharsets.UTF_8));
                manifest.add(metadata.idDocument() + ";" + docType.name() + ";" + level.name()
                        + ";" + idClient + ";" + content);
                number++;
            }
        }

        //Écrire le manifeste
        Files.write(corpus.resolve("manifest.csv"), manifest, StandardCharsets.UTF_8);
        System.out.println((number - 1) + " archives créées dans " + corpus.toAbsolutePath());
    }
}