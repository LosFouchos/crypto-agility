package fr.memoire.agility;

import java.security.GeneralSecurityException;
import java.util.Optional;

// Ce que le service d'archivage voit de la cryptographie : aucun algorithme, aucune taille, aucune clé
public interface ArchiveCrypto {

    // Signe et chiffre un contenu ; renvoie l'archive scellée (format v2)
    byte[] seal(byte[] metadataBytes, byte[] content) throws GeneralSecurityException;

    // Ouvre une archive (v2 ou historique) ; renvoie le contenu en clair ou lève une exception
    byte[] open(byte[] metadataBytes, byte[] archive) throws GeneralSecurityException;

    // Décrit la protection d'une archive à partir de son en-tête, sans clé (inventaire)
    ProtectionInfo describe(byte[] archive) throws GeneralSecurityException;

    // Re-protège une archive avec les algorithmes d'écriture actuels ;
    // vide si l'archive les utilise déjà
    Optional<byte[]> reprotect(byte[] metadataBytes, byte[] archive) throws GeneralSecurityException;
}