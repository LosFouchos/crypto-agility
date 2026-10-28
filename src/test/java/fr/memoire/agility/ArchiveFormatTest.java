package fr.memoire.agility;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class ArchiveFormatTest {

    private static ArchiveV2 sample(int protectedKeySize, int signatureSize) {
        return new ArchiveV2("KEY-PROTECTION-ID", "SIGNATURE-ID", "AES-256-GCM",
                new byte[protectedKeySize], new byte[signatureSize], new byte[]{1, 2, 3});
    }

    // E2 : aucune taille supposée. Des éléments de tailles très différentes
    // (384 octets comme RSA, 1 128 comme ML-KEM + AES Key Wrap) sont relus à l'identique
    @Test
    void elementsOfAnySizeAreReadBack() throws GeneralSecurityException {
        for (int[] sizes : new int[][]{{384, 72}, {1128, 3309}}) {
            ArchiveV2 original = sample(sizes[0], sizes[1]);

            ArchiveV2 reread = ArchiveFormat.read(ArchiveFormat.write(original));

            assertEquals(original.keyProtectionId(), reread.keyProtectionId());
            assertEquals(original.signatureId(), reread.signatureId());
            assertEquals(original.contentCipherId(), reread.contentCipherId());
            assertArrayEquals(original.protectedKey(), reread.protectedKey());
            assertArrayEquals(original.signature(), reread.signature());
            assertArrayEquals(original.encryptedContent(), reread.encryptedContent());
        }
    }

    // Une archive sans la marque CAG2 est reconnue comme archive historique
    @Test
    void dataWithoutMarkIsNotV2() {
        assertTrue(ArchiveFormat.isV2(ArchiveFormat.write(sample(384, 72))));
        assertFalse(ArchiveFormat.isV2(new byte[]{0x12, 0x34, 0x56, 0x78, 0x00}));
    }

    // Une archive tronquée est refusée, sans erreur incompréhensible plus loin
    @Test
    void truncatedArchiveIsRejected() {
        byte[] full = ArchiveFormat.write(sample(384, 72));
        byte[] truncated = Arrays.copyOf(full, 60);

        assertThrows(GeneralSecurityException.class, () -> ArchiveFormat.read(truncated));
    }

    // Une version de format inconnue est refusée
    @Test
    void unknownVersionIsRejected() {
        byte[] data = ArchiveFormat.write(sample(384, 72));
        data[4] = 9;

        assertThrows(GeneralSecurityException.class, () -> ArchiveFormat.read(data));
    }
}