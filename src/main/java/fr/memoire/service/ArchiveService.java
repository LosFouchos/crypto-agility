package fr.memoire.service;


import fr.memoire.archive.Document;
import fr.memoire.archive.DocumentRepository;
import fr.memoire.archive.Metadata;
import fr.memoire.crypto.AesGcm;
import fr.memoire.crypto.EcdsaSignature;
import fr.memoire.crypto.RsaOaep;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public class ArchiveService {

    private static final int ENVELOPE_SIZE_BYTES = 384;

    private final DocumentRepository repository;
    private final KeyPair rsaKeys;
    private final KeyPair ecdsaKeys;

    public ArchiveService(DocumentRepository repository, KeyPair rsaKeys, KeyPair ecdsaKeys) {
        this.repository = Objects.requireNonNull(repository, "Repository can't be null");
        this.rsaKeys = Objects.requireNonNull(rsaKeys, "RSA keys cannot be null");
        this.ecdsaKeys = Objects.requireNonNull(ecdsaKeys, "ECDSA keys cannot be null");
    }

    public void deposit(Metadata metadata, byte[] content)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(metadata, "Metadata cannot be null");
        Objects.requireNonNull(content, "Content cannot be null");

        byte[] metadataBytes = metadata.toBytes();

        // Signer les métadonnées et le contenu
        byte[] signature = EcdsaSignature.sign(ecdsaKeys.getPrivate(),
                concat(metadataBytes, content));

        //Chiffrer le contenu avec une clé AES neuve
        SecretKey aesKey = AesGcm.generateKey();
        byte[] encryptedContent = AesGcm.encrypt(aesKey, content, metadataBytes);

        // Protéger la clé AES avec la clé publique RSA
        byte[] envelope = RsaOaep.wrapKey(rsaKeys.getPublic(), aesKey);

        // Assembler
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(envelope);
            out.writeShort(signature.length);
            out.write(signature);
            out.write(encryptedContent);
        }

        // Enregistrer
        repository.save(new Document(metadata, buffer.toByteArray()));
    }

    public Optional<Document> consult(UUID id) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(id, "Id cannot be null");

        Optional<Document> stored = repository.findById(id);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        Metadata metadata = stored.get().metadata();
        byte[] metadataBytes = metadata.toBytes();

        byte[] envelope;
        byte[] signature;
        byte[] encryptedContent;
        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(stored.get().content()))) {
            envelope = in.readNBytes(ENVELOPE_SIZE_BYTES);
            if (envelope.length != ENVELOPE_SIZE_BYTES || in.available() < 2) {
                throw new GeneralSecurityException("Corrupted archive: envelope truncated");
            }
            int signatureLength = in.readUnsignedShort();
            signature = in.readNBytes(signatureLength);
            if (signature.length != signatureLength) {
                throw new GeneralSecurityException("Corrupted archive: signature truncated");
            }
            encryptedContent = in.readAllBytes();
        }

        SecretKey aesKey = RsaOaep.unwrapKey(rsaKeys.getPrivate(), envelope);

        byte[] content = AesGcm.decrypt(aesKey, encryptedContent, metadataBytes);

        if (!EcdsaSignature.verify(ecdsaKeys.getPublic(), concat(metadataBytes, content), signature)) {
            throw new SignatureException("Invalid signature");
        }

        return Optional.of(new Document(metadata, content));
    }




    public List<Metadata> listByClient(String idClient) throws IOException {
        return repository.findByIdClient(idClient);
    }

    private static byte[] concat(byte[] first, byte[] second) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.write(first);
        buffer.write(second);
        return buffer.toByteArray();
    }

}
