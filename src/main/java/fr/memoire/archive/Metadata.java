package fr.memoire.archive;

import java.time.Instant;
import java.time.Period;
import java.util.Objects;
import java.util.UUID;

public record Metadata(UUID idDocument, ConfidentialityLevel confidentialityLevel, DocType docType,  String idClient, Instant dateDepot, Period durationConservation)  {

    public Metadata {
        Objects.requireNonNull(confidentialityLevel, "ConfidentialityLevel cannot be null");
        Objects.requireNonNull(docType, "DocType cannot be null");
        Objects.requireNonNull(idDocument, "IdDocument cannot be null");
        Objects.requireNonNull(idClient, "IdClient cannot be null");
        Objects.requireNonNull(dateDepot, "DateDepot cannot be null");
        Objects.requireNonNull(durationConservation, "DurationConservation cannot be null");
        if(durationConservation.isNegative()) {
            throw new IllegalArgumentException("DurationConservation cannot be negative");
        }
        if(durationConservation.isZero()) {
            throw new IllegalArgumentException("DurationConservation cannot be zero");
        }
    }
}
