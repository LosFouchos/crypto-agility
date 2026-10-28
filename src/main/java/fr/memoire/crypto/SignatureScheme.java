package fr.memoire.crypto;

import java.security.GeneralSecurityException;

// Signature des archives. Chaque implémentation possède ses propres clés.
public interface SignatureScheme {

    // Identifiant stable, écrit dans l'en-tête des archives (ex. "ECDSA-P256-SHA256")
    String id();

    byte[] sign(byte[] data) throws GeneralSecurityException;

    // Renvoie false pour toute signature invalide
    boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException;
}