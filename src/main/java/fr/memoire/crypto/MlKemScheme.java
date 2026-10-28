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

// Protection de la clé AES par ML-KEM-768 (FIPS 203), puis HKDF-SHA256 et AES Key Wrap 256.
// Clé protégée : longueur de l'encapsulation (4 octets) | encapsulation (1 088 octets) | clé AES enveloppée (40 octets)
public final class MlKemScheme implements KeyProtectionScheme {

    public static final String ID = "ML-KEM-768-HKDF-SHA256-AESKW256";
    private static final String PARAMETER_SET = "ML-KEM-768";

    private final KeyPair keys;

    public MlKemScheme(KeyPair keys) throws InvalidKeyException {
        Objects.requireNonNull(keys, "Keys cannot be null");
        // L'identifiant promet ML-KEM-768 : tout autre jeu de paramètres est refusé dès la construction
        if (!KemKeyWrap.hasParameterSet(keys.getPublic(), PARAMETER_SET)) {
            throw new InvalidKeyException(ID + " requires an " + PARAMETER_SET + " key");
        }
        this.keys = keys;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public byte[] protect(SecretKey dataKey) throws GeneralSecurityException {
        KEM.Encapsulated encapsulated = KEM.getInstance("ML-KEM").newEncapsulator(keys.getPublic()).encapsulate();
        byte[] encapsulation = encapsulated.encapsulation();
        SecretKey kek = KemKeyWrap.deriveKek(List.of(encapsulated.key()), info(encapsulation));
        byte[] wrappedKey = KemKeyWrap.wrap(kek, dataKey);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(encapsulation.length);
            out.write(encapsulation);
            out.write(wrappedKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buffer.toByteArray();
    }

    @Override
    public SecretKey unprotect(byte[] protectedKey) throws GeneralSecurityException {
        Objects.requireNonNull(protectedKey, "Protected key cannot be null");
        byte[] encapsulation;
        byte[] wrappedKey;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(protectedKey))) {
            int length = in.readInt();
            if (length < 0 || length > in.available()) {
                throw new GeneralSecurityException("Corrupted protected key");
            }
            encapsulation = in.readNBytes(length);
            wrappedKey = in.readAllBytes();
        } catch (IOException e) {
            throw new GeneralSecurityException("Corrupted protected key", e);
        }
        // Rejet implicite : une encapsulation altérée donne un autre secret, sans erreur ;
        // c'est l'ouverture par AES Key Wrap qui échouera
        SecretKey sharedSecret = KEM.getInstance("ML-KEM").newDecapsulator(keys.getPrivate()).decapsulate(encapsulation);
        SecretKey kek = KemKeyWrap.deriveKek(List.of(sharedSecret), info(encapsulation));
        return KemKeyWrap.unwrap(kek, wrappedKey);
    }

    // Contexte de dérivation : l'identifiant et l'encapsulation, pour lier la clé de protection à cet usage
    private static byte[] info(byte[] encapsulation) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.writeBytes(ID.getBytes(StandardCharsets.UTF_8));
        buffer.writeBytes(encapsulation);
        return buffer.toByteArray();
    }
}