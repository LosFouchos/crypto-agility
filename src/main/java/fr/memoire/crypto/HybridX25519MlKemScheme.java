package fr.memoire.crypto;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.List;
import java.util.Objects;

// Protection hybride de la clé AES : X25519 (classique) ET ML-KEM-768 (post-quantique).
// Les deux secrets sont combinés dans une seule dérivation HKDF-SHA256 : la clé AES reste protégée
// tant que l'un des deux algorithmes n'est pas cassé. Puis AES Key Wrap 256.
// Clé protégée : longueur + encapsulation X25519 (32 octets) | longueur + encapsulation ML-KEM (1 088 octets)
//                | clé AES enveloppée (40 octets)
public final class HybridX25519MlKemScheme implements KeyProtectionScheme {

    public static final String ID = "X25519-ML-KEM-768-HKDF-SHA256-AESKW256";

    private final KeyPair x25519Keys;
    private final KeyPair mlKemKeys;

    public HybridX25519MlKemScheme(KeyPair x25519Keys, KeyPair mlKemKeys) throws InvalidKeyException {
        Objects.requireNonNull(x25519Keys, "X25519 keys cannot be null");
        Objects.requireNonNull(mlKemKeys, "ML-KEM keys cannot be null");
        // L'identifiant promet X25519 et ML-KEM-768 : toute autre clé est refusée dès la construction
        if (!KemKeyWrap.hasParameterSet(x25519Keys.getPublic(), "X25519")
                || !KemKeyWrap.hasParameterSet(mlKemKeys.getPublic(), "ML-KEM-768")) {
            throw new InvalidKeyException(ID + " requires an X25519 key and an ML-KEM-768 key");
        }
        this.x25519Keys = x25519Keys;
        this.mlKemKeys = mlKemKeys;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public byte[] protect(SecretKey dataKey) throws GeneralSecurityException {
        KEM.Encapsulated classical = KEM.getInstance("DHKEM").newEncapsulator(x25519Keys.getPublic()).encapsulate();
        KEM.Encapsulated postQuantum = KEM.getInstance("ML-KEM").newEncapsulator(mlKemKeys.getPublic()).encapsulate();
        byte[] classicalEncapsulation = classical.encapsulation();
        byte[] postQuantumEncapsulation = postQuantum.encapsulation();

        SecretKey kek = KemKeyWrap.deriveKek(List.of(classical.key(), postQuantum.key()),
                info(classicalEncapsulation, postQuantumEncapsulation));
        byte[] wrappedKey = KemKeyWrap.wrap(kek, dataKey);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(classicalEncapsulation.length);
            out.write(classicalEncapsulation);
            out.writeInt(postQuantumEncapsulation.length);
            out.write(postQuantumEncapsulation);
            out.write(wrappedKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buffer.toByteArray();
    }

    @Override
    public SecretKey unprotect(byte[] protectedKey) throws GeneralSecurityException {
        Objects.requireNonNull(protectedKey, "Protected key cannot be null");
        byte[] classicalEncapsulation;
        byte[] postQuantumEncapsulation;
        byte[] wrappedKey;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(protectedKey))) {
            classicalEncapsulation = readWithLength(in);
            postQuantumEncapsulation = readWithLength(in);
            wrappedKey = in.readAllBytes();
        } catch (IOException e) {
            throw new GeneralSecurityException("Corrupted protected key", e);
        }

        SecretKey classical = KEM.getInstance("DHKEM").newDecapsulator(x25519Keys.getPrivate())
                .decapsulate(classicalEncapsulation);
        SecretKey postQuantum = KEM.getInstance("ML-KEM").newDecapsulator(mlKemKeys.getPrivate())
                .decapsulate(postQuantumEncapsulation);
        // Il faut les DEUX secrets pour retrouver la clé de protection
        SecretKey kek = KemKeyWrap.deriveKek(List.of(classical, postQuantum),
                info(classicalEncapsulation, postQuantumEncapsulation));
        return KemKeyWrap.unwrap(kek, wrappedKey);
    }

    private static byte[] readWithLength(DataInputStream in) throws IOException, GeneralSecurityException {
        int length = in.readInt();
        if (length < 0 || length > in.available()) {
            throw new GeneralSecurityException("Corrupted protected key");
        }
        return in.readNBytes(length);
    }

    // Contexte de dérivation : l'identifiant et les deux encapsulations
    private static byte[] info(byte[] classicalEncapsulation, byte[] postQuantumEncapsulation) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.writeBytes(ID.getBytes(StandardCharsets.UTF_8));
        buffer.writeBytes(classicalEncapsulation);
        buffer.writeBytes(postQuantumEncapsulation);
        return buffer.toByteArray();
    }
}