package fr.memoire.archive;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.Period;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class MetadataTest {

    private static final UUID IDDOCUMENT = UUID.randomUUID();
    private static final String CLIENT = "CLI-0001";
    private static final Instant DEPOT = Instant.now();
    private static final Period DUREE = Period.ofYears(10);


    @Test
    void acceptsValidMetadata() {
        assertDoesNotThrow(() -> new Metadata(IDDOCUMENT,ConfidentialityLevel.CONFIDENTIEL,DocType.CONTRAT, CLIENT, DEPOT, DUREE)
        );
    }

    @Test
    void rejectsNullDocumentId(){
        assertThrows(NullPointerException.class, ()-> new Metadata(null, ConfidentialityLevel.CONFIDENTIEL, DocType.CONTRAT,CLIENT,DEPOT,DUREE)
        );
    }

    @Test
    void rejectsNegativeRetention(){
        var e = assertThrows(IllegalArgumentException.class, () -> new Metadata(IDDOCUMENT, ConfidentialityLevel.CONFIDENTIEL,DocType.CONTRAT,CLIENT,DEPOT,Period.ofYears(-1))
        );
        assertEquals("DurationConservation cannot be negative",e.getMessage());

    }

    @Test
    void rejectsZeroRetention(){
        var e = assertThrows(IllegalArgumentException.class, () -> new Metadata(IDDOCUMENT,ConfidentialityLevel.CONFIDENTIEL,DocType.CONTRAT,CLIENT,DEPOT,Period.ZERO)
        );
        assertEquals("DurationConservation cannot be zero", e.getMessage());
    }

}