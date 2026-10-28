package fr.memoire.agility;

import fr.memoire.corpus.KeyFiles;
import fr.memoire.crypto.EcdsaScheme;
import fr.memoire.crypto.KeyProtectionScheme;
import fr.memoire.crypto.RsaOaepScheme;
import fr.memoire.crypto.SignatureScheme;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import fr.memoire.crypto.MlDsaScheme;
import fr.memoire.crypto.MlKemScheme;
import java.util.ArrayList;

import fr.memoire.crypto.HybridX25519MlKemScheme;

// Briques disponibles, chacune avec ses clés, retrouvées par leur identifiant
public final class SchemeRegistry {

    private final Map<String, KeyProtectionScheme> keyProtections = new HashMap<>();
    private final Map<String, SignatureScheme> signatures = new HashMap<>();
    private final LegacyV1Reader legacyReader;

    public SchemeRegistry(List<KeyProtectionScheme> keyProtections, List<SignatureScheme> signatures,
                          LegacyV1Reader legacyReader) {
        Objects.requireNonNull(keyProtections, "Key protections cannot be null");
        Objects.requireNonNull(signatures, "Signatures cannot be null");
        keyProtections.forEach(scheme -> this.keyProtections.put(scheme.id(), scheme));
        signatures.forEach(scheme -> this.signatures.put(scheme.id(), scheme));
        this.legacyReader = legacyReader; // peut être null : aucune archive historique à lire
    }

    // Construit le registre à partir des clés présentes dans un dossier (fichiers <nom>.pub et <nom>.key)
    public static SchemeRegistry load(Path keyDirectory) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(keyDirectory, "Key directory cannot be null");
        KeyPair rsa = loadIfPresent(keyDirectory, "rsa", "RSA");
        KeyPair ecdsa = loadIfPresent(keyDirectory, "ecdsa", "EC");
        KeyPair mlKem = loadIfPresent(keyDirectory, "mlkem", "ML-KEM");
        KeyPair mlDsa = loadIfPresent(keyDirectory, "mldsa", "ML-DSA");
        KeyPair x25519 = loadIfPresent(keyDirectory, "x25519", "XDH");

        List<KeyProtectionScheme> keyProtections = new ArrayList<>();
        List<SignatureScheme> signatures = new ArrayList<>();
        if (rsa != null) keyProtections.add(new RsaOaepScheme(rsa));
        if (mlKem != null) keyProtections.add(new MlKemScheme(mlKem));
        if (x25519 != null && mlKem != null) keyProtections.add(new HybridX25519MlKemScheme(x25519, mlKem));
        if (ecdsa != null) signatures.add(new EcdsaScheme(ecdsa));
        if (mlDsa != null) signatures.add(new MlDsaScheme(mlDsa));
        LegacyV1Reader legacy = (rsa == null || ecdsa == null) ? null : new LegacyV1Reader(rsa, ecdsa);
        return new SchemeRegistry(keyProtections, signatures, legacy);
    }

    private static KeyPair loadIfPresent(Path directory, String name, String algorithm)
            throws IOException, GeneralSecurityException {
        if (!Files.exists(directory.resolve(name + ".pub"))) {
            return null;
        }
        return KeyFiles.load(directory, name, algorithm);
    }

    public Optional<KeyProtectionScheme> keyProtection(String id) {
        return Optional.ofNullable(keyProtections.get(id));
    }

    public Optional<SignatureScheme> signature(String id) {
        return Optional.ofNullable(signatures.get(id));
    }

    public Optional<LegacyV1Reader> legacyReader() {
        return Optional.ofNullable(legacyReader);
    }
}