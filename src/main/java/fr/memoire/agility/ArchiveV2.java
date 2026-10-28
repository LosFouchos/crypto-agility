package fr.memoire.agility;

import java.util.Objects;

// Contenu d'une archive au format v2, une fois découpée (voir ArchiveFormat)
public record ArchiveV2(String keyProtectionId, String signatureId, String contentCipherId,
                        byte[] protectedKey, byte[] signature, byte[] encryptedContent) {

    public ArchiveV2 {
        Objects.requireNonNull(keyProtectionId, "Key protection id cannot be null");
        Objects.requireNonNull(signatureId, "Signature id cannot be null");
        Objects.requireNonNull(contentCipherId, "Content cipher id cannot be null");
        protectedKey = Objects.requireNonNull(protectedKey, "Protected key cannot be null").clone();
        signature = Objects.requireNonNull(signature, "Signature cannot be null").clone();
        encryptedContent = Objects.requireNonNull(encryptedContent, "Encrypted content cannot be null").clone();
    }

    @Override
    public byte[] protectedKey() {
        return protectedKey.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public byte[] encryptedContent() {
        return encryptedContent.clone();
    }

    // Même archive avec une autre enveloppe : contenu chiffré et signature inchangés (re-protection)
    public ArchiveV2 withKeyProtection(String newKeyProtectionId, byte[] newProtectedKey) {
        return new ArchiveV2(newKeyProtectionId, signatureId, contentCipherId,
                newProtectedKey, signature, encryptedContent);
    }
}