package fr.memoire.agility;

// Description d'une archive, lue dans son en-tête sans aucune clé (inventaire, E5).
// format vaut "CAG2" pour une archive v2, ou "LEGACY-V1" pour une archive historique.
public record ProtectionInfo(String format, String keyProtectionId, String signatureId,
                             String contentCipherId) {
}