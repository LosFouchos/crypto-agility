package fr.memoire.agility;

import fr.memoire.crypto.EcdsaScheme;
import fr.memoire.crypto.RsaOaepScheme;

import java.util.Map;
import java.util.Optional;

import fr.memoire.crypto.MlDsaScheme;
import fr.memoire.crypto.MlKemScheme;

import fr.memoire.crypto.HybridX25519MlKemScheme;

// Liste des identifiants que la couche sait traiter, avec leur famille.
// Un identifiant absent de ce catalogue est inconnu : la politique le refuse.
public final class AlgorithmCatalog {

    public static final String LEGACY_V1 = "LEGACY-V1";

    private static final Map<String, AlgorithmFamily> KNOWN = Map.of(
            RsaOaepScheme.ID, AlgorithmFamily.KEY_PROTECTION,
            EcdsaScheme.ID, AlgorithmFamily.SIGNATURE,
            MlKemScheme.ID, AlgorithmFamily.KEY_PROTECTION,
            HybridX25519MlKemScheme.ID, AlgorithmFamily.KEY_PROTECTION,
            MlDsaScheme.ID, AlgorithmFamily.SIGNATURE,
            LEGACY_V1, AlgorithmFamily.FORMAT
    );

    private AlgorithmCatalog() { }

    public static Optional<AlgorithmFamily> familyOf(String id) {
        return Optional.ofNullable(KNOWN.get(id));
    }
}