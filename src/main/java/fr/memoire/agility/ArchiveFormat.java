package fr.memoire.agility;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

// Format d'archive v2, auto-descriptif :
//   1. marque "CAG2" (4 octets)                  -- authentifié
//   2. version du format (1 octet)               -- authentifié
//   3. identifiant de protection de clé          -- NON authentifié (remplaçable sans rechiffrer)
//   4. identifiant de signature                  -- authentifié
//   5. identifiant du chiffrement du contenu     -- authentifié
//   6. clé AES protégée   (longueur sur 4 octets) -- NON authentifiée (remplaçable sans rechiffrer)
//   7. signature          (longueur sur 4 octets)
//   8. contenu chiffré    (le reste)
// Les identifiants sont écrits avec writeUTF (longueur sur 2 octets, puis le texte).
// Aucune taille d'élément n'est supposée.
public final class ArchiveFormat {

    private static final byte[] MAGIC = {'C', 'A', 'G', '2'};
    private static final int VERSION = 1;

    private ArchiveFormat() { }

    // Une archive v2 commence par la marque ; sinon, c'est une archive historique (LEGACY-V1)
    public static boolean isV2(byte[] data) {
        Objects.requireNonNull(data, "Data cannot be null");
        return data.length >= MAGIC.length
                && Arrays.equals(Arrays.copyOf(data, MAGIC.length), MAGIC);
    }

    // Éléments 1, 2, 4 et 5 mis bout à bout : la partie de l'en-tête protégée
    // par les données associées d'AES-GCM et par la signature
    public static byte[] authenticatedHeader(String signatureId, String contentCipherId) {
        Objects.requireNonNull(signatureId, "Signature id cannot be null");
        Objects.requireNonNull(contentCipherId, "Content cipher id cannot be null");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeUTF(signatureId);
            out.writeUTF(contentCipherId);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buffer.toByteArray();
    }

    public static byte[] write(ArchiveV2 archive) {
        Objects.requireNonNull(archive, "Archive cannot be null");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeUTF(archive.keyProtectionId());
            out.writeUTF(archive.signatureId());
            out.writeUTF(archive.contentCipherId());
            writeWithLength(out, archive.protectedKey());
            writeWithLength(out, archive.signature());
            out.write(archive.encryptedContent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buffer.toByteArray();
    }

    public static ArchiveV2 read(byte[] data) throws GeneralSecurityException {
        if (!isV2(data)) {
            throw new GeneralSecurityException("Not a v2 archive");
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            in.skipNBytes(MAGIC.length);
            int version = in.readUnsignedByte();
            if (version != VERSION) {
                throw new GeneralSecurityException("Unsupported archive version: " + version);
            }
            String keyProtectionId = in.readUTF();
            String signatureId = in.readUTF();
            String contentCipherId = in.readUTF();
            byte[] protectedKey = readWithLength(in);
            byte[] signature = readWithLength(in);
            byte[] encryptedContent = in.readAllBytes();
            return new ArchiveV2(keyProtectionId, signatureId, contentCipherId,
                    protectedKey, signature, encryptedContent);
        } catch (IOException e) {
            // Archive tronquée ou mal formée
            throw new GeneralSecurityException("Corrupted archive", e);
        }
    }

    private static void writeWithLength(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    private static byte[] readWithLength(DataInputStream in) throws IOException, GeneralSecurityException {
        int length = in.readInt();
        if (length < 0 || length > in.available()) {
            throw new GeneralSecurityException("Corrupted archive: invalid length " + length);
        }
        return in.readNBytes(length);
    }
}