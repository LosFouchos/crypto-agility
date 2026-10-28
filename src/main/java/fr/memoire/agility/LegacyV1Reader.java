package fr.memoire.agility;

import fr.memoire.crypto.AesGcm;
import fr.memoire.crypto.EcdsaSignature;
import fr.memoire.crypto.RsaOaep;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.util.Objects;

// Lecteur des archives historiques (format v1, identifiant LEGACY-V1).
// Seul endroit de l'application qui connaît encore ce format :
//   enveloppe RSA (384 octets) | longueur de la signature (2 octets) | signature ECDSA | contenu chiffré
// Le format v1 n'indiquant aucun algorithme, ils sont écrits ici en dur, comme dans la version de référence.
public final class LegacyV1Reader {

    // Taille de l'enveloppe RSA-3072 : hypothèse propre au format v1
    private static final int ENVELOPE_SIZE_BYTES = 384;

    private final KeyPair rsaKeys;
    private final KeyPair ecdsaKeys;

    public LegacyV1Reader(KeyPair rsaKeys, KeyPair ecdsaKeys) {
        this.rsaKeys = Objects.requireNonNull(rsaKeys, "RSA keys cannot be null");
        this.ecdsaKeys = Objects.requireNonNull(ecdsaKeys, "ECDSA keys cannot be null");
    }

    // Ouvre une archive v1 : découper, ouvrir l'enveloppe, déchiffrer, PUIS vérifier la signature
    public byte[] open(byte[] metadataBytes, byte[] data) throws GeneralSecurityException {
        Objects.requireNonNull(metadataBytes, "Metadata bytes cannot be null");
        Objects.requireNonNull(data, "Data cannot be null");

        byte[] envelope;
        byte[] signature;
        byte[] encryptedContent;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            envelope = in.readNBytes(ENVELOPE_SIZE_BYTES);
            if (envelope.length != ENVELOPE_SIZE_BYTES || in.available() < 2) {
                throw new GeneralSecurityException("Corrupted v1 archive: envelope truncated");
            }
            int signatureLength = in.readUnsignedShort();
            signature = in.readNBytes(signatureLength);
            if (signature.length != signatureLength) {
                throw new GeneralSecurityException("Corrupted v1 archive: signature truncated");
            }
            encryptedContent = in.readAllBytes();
        } catch (IOException e) {
            throw new GeneralSecurityException("Corrupted v1 archive", e);
        }

        SecretKey aesKey = RsaOaep.unwrapKey(rsaKeys.getPrivate(), envelope);
        byte[] content = AesGcm.decrypt(aesKey, encryptedContent, metadataBytes);

        // Vérifier APRÈS le déchiffrement : la signature v1 porte sur métadonnées + contenu en clair
        if (!EcdsaSignature.verify(ecdsaKeys.getPublic(), concat(metadataBytes, content), signature)) {
            throw new SignatureException("Invalid signature");
        }
        return content;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.writeBytes(first);
        buffer.writeBytes(second);
        return buffer.toByteArray();
    }
}