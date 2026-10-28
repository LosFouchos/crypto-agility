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

        List<KeyProtectionScheme> keyProtections = rsa == null ? List.of() : List.of(new RsaOaepScheme(rsa));
        List<SignatureScheme> signatures = ecdsa == null ? List.of() : List.of(new EcdsaScheme(ecdsa));
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