package fr.memoire.crypto;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

// Protection de la clé AES d'un document.
public interface KeyProtectionScheme {

    // Identifiant dans l'en-tête des archives
    String id();

    byte[] protect(SecretKey dataKey) throws GeneralSecurityException;

    SecretKey unprotect(byte[] protectedKey) throws GeneralSecurityException;
}