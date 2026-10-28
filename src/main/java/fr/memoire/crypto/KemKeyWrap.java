package fr.memoire.crypto;

import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.AsymmetricKey;
import java.security.spec.NamedParameterSpec;
import java.util.List;

// Outils communs aux briques à encapsulation de clés (ML-KEM, hybride), sur le modèle des RFC 9629 et 9936 :
// le ou les secrets encapsulés sont dérivés par HKDF-SHA256 en une clé de protection,
// qui protège la clé AES par AES Key Wrap (RFC 3394).
final class KemKeyWrap {

    private static final String KDF_ALGORITHM = "HKDF-SHA256";
    private static final String KEY_WRAP = "AES/KW/NoPadding";
    private static final int KEK_SIZE_BYTES = 32;

    private KemKeyWrap() { }

    // Dérive la clé de protection à partir de TOUS les secrets : elle reste sûre tant que l'un d'eux l'est
    static SecretKey deriveKek(List<SecretKey> sharedSecrets, byte[] info) throws GeneralSecurityException {
        HKDFParameterSpec.Builder extract = HKDFParameterSpec.ofExtract();
        for (SecretKey secret : sharedSecrets) {
            extract.addIKM(secret);
        }
        return KDF.getInstance(KDF_ALGORITHM).deriveKey("AES", extract.thenExpand(info, KEK_SIZE_BYTES));
    }

    static byte[] wrap(SecretKey kek, SecretKey dataKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(KEY_WRAP);
        cipher.init(Cipher.WRAP_MODE, kek);
        return cipher.wrap(dataKey);
    }

    // Échoue si la clé de protection est fausse : c'est ce contrôle d'intégrité qui révèle une encapsulation
    // altérée, car ML-KEM ne signale jamais d'erreur (rejet implicite)
    static SecretKey unwrap(SecretKey kek, byte[] wrappedKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(KEY_WRAP);
        cipher.init(Cipher.UNWRAP_MODE, kek);
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    // Vérifie le jeu de paramètres d'une clé post-quantique (ex. "ML-KEM-768")
    static boolean hasParameterSet(Key key, String parameterSet) {
        return key instanceof AsymmetricKey asymmetricKey
                && asymmetricKey.getParams() instanceof NamedParameterSpec spec
                && spec.getName().equalsIgnoreCase(parameterSet);
    }
}