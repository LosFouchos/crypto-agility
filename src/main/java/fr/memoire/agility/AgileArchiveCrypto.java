package fr.memoire.agility;

import fr.memoire.crypto.AesGcm;
import fr.memoire.crypto.EcdsaScheme;
import fr.memoire.crypto.KeyProtectionScheme;
import fr.memoire.crypto.RsaOaepScheme;
import fr.memoire.crypto.SignatureScheme;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Optional;

// La couche crypto-agile : applique la politique, choisit les briques, écrit et lit le format v2,
// et délègue les archives historiques au lecteur v1
public final class AgileArchiveCrypto implements ArchiveCrypto {

    // Chiffrement du contenu écrit en dur (choix assumé, cf. limites) mais déclaré dans chaque archive
    static final String CONTENT_CIPHER_ID = "AES-256-GCM";

    private final CryptoPolicy policy;
    private final SchemeRegistry registry;

    public AgileArchiveCrypto(CryptoPolicy policy, SchemeRegistry registry) {
        this.policy = Objects.requireNonNull(policy, "Policy cannot be null");
        this.registry = Objects.requireNonNull(registry, "Registry cannot be null");
        // Configuration incohérente : la politique demande d'écrire avec une brique sans clés
        if (registry.keyProtection(policy.writeKeyProtection()).isEmpty()
                || registry.signature(policy.writeSignature()).isEmpty()) {
            throw new InvalidPolicyException("No keys available for the write algorithms of the policy");
        }
    }

    @Override
    public byte[] seal(byte[] metadataBytes, byte[] content) throws GeneralSecurityException {
        Objects.requireNonNull(metadataBytes, "Metadata bytes cannot be null");
        Objects.requireNonNull(content, "Content cannot be null");

        KeyProtectionScheme keyProtection = writeKeyProtection();
        SignatureScheme signer = registry.signature(policy.writeSignature()).orElseThrow();
        policy.requireWritable(signer.id());

        // Données associées = métadonnées + en-tête authentifié ; données signées = celles-ci + contenu en clair
        byte[] aad = concat(metadataBytes, ArchiveFormat.authenticatedHeader(signer.id(), CONTENT_CIPHER_ID));
        byte[] signature = signer.sign(concat(aad, content));

        SecretKey aesKey = AesGcm.generateKey();
        byte[] encryptedContent = AesGcm.encrypt(aesKey, content, aad);
        byte[] protectedKey = keyProtection.protect(aesKey);

        return ArchiveFormat.write(new ArchiveV2(keyProtection.id(), signer.id(), CONTENT_CIPHER_ID,
                protectedKey, signature, encryptedContent));
    }

    @Override
    public byte[] open(byte[] metadataBytes, byte[] archive) throws GeneralSecurityException {
        Objects.requireNonNull(metadataBytes, "Metadata bytes cannot be null");
        Objects.requireNonNull(archive, "Archive cannot be null");

        if (!ArchiveFormat.isV2(archive)) {
            return openLegacy(metadataBytes, archive);
        }
        ArchiveV2 parsed = ArchiveFormat.read(archive);

        // La politique est consultée AVANT toute opération cryptographique
        KeyProtectionScheme keyProtection = readableKeyProtection(parsed.keyProtectionId());
        SignatureScheme verifier = readableSignature(parsed.signatureId());
        requireContentCipher(parsed.contentCipherId());

        SecretKey aesKey = keyProtection.unprotect(parsed.protectedKey());
        byte[] aad = concat(metadataBytes,
                ArchiveFormat.authenticatedHeader(parsed.signatureId(), parsed.contentCipherId()));
        byte[] content = AesGcm.decrypt(aesKey, parsed.encryptedContent(), aad);

        // Vérifier APRÈS le déchiffrement : la signature porte sur le contenu en clair
        if (!verifier.verify(concat(aad, content), parsed.signature())) {
            throw new SignatureException("Invalid signature");
        }
        return content;
    }

    @Override
    public ProtectionInfo describe(byte[] archive) throws GeneralSecurityException {
        Objects.requireNonNull(archive, "Archive cannot be null");
        if (!ArchiveFormat.isV2(archive)) {
            // Le format v1 n'indique rien : ses algorithmes sont connus par convention
            return new ProtectionInfo(AlgorithmCatalog.LEGACY_V1, RsaOaepScheme.ID, EcdsaScheme.ID,
                    CONTENT_CIPHER_ID);
        }
        ArchiveV2 parsed = ArchiveFormat.read(archive);
        return new ProtectionInfo("CAG2", parsed.keyProtectionId(), parsed.signatureId(),
                parsed.contentCipherId());
    }

    @Override
    public Optional<byte[]> reprotect(byte[] metadataBytes, byte[] archive) throws GeneralSecurityException {
        Objects.requireNonNull(metadataBytes, "Metadata bytes cannot be null");
        Objects.requireNonNull(archive, "Archive cannot be null");

        // Archive historique : la sceller entièrement au format v2 (rechiffrement et nouvelle signature)
        if (!ArchiveFormat.isV2(archive)) {
            return Optional.of(seal(metadataBytes, open(metadataBytes, archive)));
        }
        ArchiveV2 parsed = ArchiveFormat.read(archive);

        // Signature à renouveler : il faut re-signer le contenu en clair, donc tout re-sceller
        if (!parsed.signatureId().equals(policy.writeSignature())) {
            return Optional.of(seal(metadataBytes, open(metadataBytes, archive)));
        }
        // Seule l'enveloppe est à remplacer : contenu chiffré et signature conservés à l'identique
        if (!parsed.keyProtectionId().equals(policy.writeKeyProtection())) {
            SecretKey aesKey = readableKeyProtection(parsed.keyProtectionId()).unprotect(parsed.protectedKey());
            KeyProtectionScheme newKeyProtection = writeKeyProtection();
            return Optional.of(ArchiveFormat.write(
                    parsed.withKeyProtection(newKeyProtection.id(), newKeyProtection.protect(aesKey))));
        }
        return Optional.empty();
    }

    private byte[] openLegacy(byte[] metadataBytes, byte[] archive) throws GeneralSecurityException {
        policy.requireReadable(AlgorithmCatalog.LEGACY_V1);
        LegacyV1Reader reader = registry.legacyReader()
                .orElseThrow(() -> new AlgorithmRejectedException("No keys available for " + AlgorithmCatalog.LEGACY_V1));
        return reader.open(metadataBytes, archive);
    }

    private KeyProtectionScheme writeKeyProtection() throws GeneralSecurityException {
        String id = policy.writeKeyProtection();
        policy.requireWritable(id);
        return registry.keyProtection(id).orElseThrow();
    }

    private KeyProtectionScheme readableKeyProtection(String id) throws GeneralSecurityException {
        policy.requireReadable(id);
        return registry.keyProtection(id)
                .orElseThrow(() -> new AlgorithmRejectedException("No keys available for " + id));
    }

    private SignatureScheme readableSignature(String id) throws GeneralSecurityException {
        policy.requireReadable(id);
        return registry.signature(id)
                .orElseThrow(() -> new AlgorithmRejectedException("No keys available for " + id));
    }

    private static void requireContentCipher(String id) throws AlgorithmRejectedException {
        if (!CONTENT_CIPHER_ID.equals(id)) {
            throw new AlgorithmRejectedException("Unsupported content cipher: " + id);
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        buffer.writeBytes(first);
        buffer.writeBytes(second);
        return buffer.toByteArray();
    }
}