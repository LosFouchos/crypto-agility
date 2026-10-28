package fr.memoire.agility;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

// Politique cryptographique, lue dans un fichier de configuration et validée dès son chargement.
// Format :
//   write.keyProtection = <identifiant>
//   write.signature     = <identifiant>
//   state.<identifiant> = ALLOWED | READ_ONLY | FORBIDDEN
public final class CryptoPolicy {

    private static final String WRITE_KEY_PROTECTION = "write.keyProtection";
    private static final String WRITE_SIGNATURE = "write.signature";
    private static final String STATE_PREFIX = "state.";

    private final String writeKeyProtection;
    private final String writeSignature;
    private final Map<String, AlgorithmState> states;

    private CryptoPolicy(String writeKeyProtection, String writeSignature,
                         Map<String, AlgorithmState> states) {
        this.writeKeyProtection = writeKeyProtection;
        this.writeSignature = writeSignature;
        this.states = Map.copyOf(states);
    }

    public static CryptoPolicy load(Path file) throws IOException {
        Objects.requireNonNull(file, "Policy file cannot be null");
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file)) {
            properties.load(reader);
        }
        return from(properties);
    }

    public static CryptoPolicy from(Properties properties) {
        Objects.requireNonNull(properties, "Properties cannot be null");

        // Lire les états, en refusant toute clé inconnue, tout identifiant inconnu et tout état invalide
        Map<String, AlgorithmState> states = new HashMap<>();
        for (String key : properties.stringPropertyNames()) {
            String value = properties.getProperty(key).trim();
            if (key.equals(WRITE_KEY_PROTECTION) || key.equals(WRITE_SIGNATURE)) {
                continue;
            }
            if (!key.startsWith(STATE_PREFIX)) {
                throw new InvalidPolicyException("Unknown policy entry: " + key);
            }
            String id = key.substring(STATE_PREFIX.length());
            requireKnown(id);
            try {
                states.put(id, AlgorithmState.valueOf(value));
            } catch (IllegalArgumentException e) {
                throw new InvalidPolicyException("Invalid state for " + id + ": " + value);
            }
        }

        // Valider les deux algorithmes d'écriture
        String writeKeyProtection = requireWriteAlgorithm(properties, WRITE_KEY_PROTECTION,
                AlgorithmFamily.KEY_PROTECTION, states);
        String writeSignature = requireWriteAlgorithm(properties, WRITE_SIGNATURE,
                AlgorithmFamily.SIGNATURE, states);

        return new CryptoPolicy(writeKeyProtection, writeSignature, states);
    }

    private static String requireWriteAlgorithm(Properties properties, String key,
                                                AlgorithmFamily expectedFamily,
                                                Map<String, AlgorithmState> states) {
        String id = properties.getProperty(key);
        if (id == null || id.isBlank()) {
            throw new InvalidPolicyException("Missing write algorithm: " + key);
        }
        id = id.trim();
        AlgorithmFamily family = requireKnown(id);
        if (family != expectedFamily) {
            throw new InvalidPolicyException(key + " must be a " + expectedFamily + " algorithm, not " + id);
        }
        if (states.get(id) != AlgorithmState.ALLOWED) {
            throw new InvalidPolicyException("Write algorithm " + id + " must be ALLOWED");
        }
        return id;
    }

    private static AlgorithmFamily requireKnown(String id) {
        return AlgorithmCatalog.familyOf(id)
                .orElseThrow(() -> new InvalidPolicyException("Unknown algorithm: " + id));
    }

    public String writeKeyProtection() {
        return writeKeyProtection;
    }

    public String writeSignature() {
        return writeSignature;
    }

    // Refus par défaut : un algorithme absent de la politique est considéré comme interdit
    public AlgorithmState stateOf(String id) {
        return states.getOrDefault(id, AlgorithmState.FORBIDDEN);
    }

    public void requireWritable(String id) throws AlgorithmRejectedException {
        if (stateOf(id) != AlgorithmState.ALLOWED) {
            throw new AlgorithmRejectedException("Algorithm not allowed for writing: " + id);
        }
    }

    public void requireReadable(String id) throws AlgorithmRejectedException {
        if (stateOf(id) == AlgorithmState.FORBIDDEN) {
            throw new AlgorithmRejectedException("Algorithm not allowed for reading: " + id);
        }
    }
}