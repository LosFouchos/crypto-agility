package fr.memoire.archive;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Period;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DocumentTest {

    private static final UUID IDDOCUMENT = UUID.randomUUID();
    private static final String CLIENT = "CLI-0001";
    private static final Instant DEPOT = Instant.now();
    private static final Period DUREE = Period.ofYears(10);
    private static final Metadata METADATA_TEST = new Metadata(IDDOCUMENT,ConfidentialityLevel.CONFIDENTIEL,DocType.CONTRAT,CLIENT,DEPOT,DUREE);

    @Test
    void isNotAffectedByChangeInOriginalArray(){

        byte[] original = {1,2,3};

        Document document = new Document(METADATA_TEST, original);

        original[0] = 99;
        assertArrayEquals(new byte[] {1, 2, 3}, document.content());

    }

    @Test
    void isNotAffectedByChangeToReturnArray(){
        byte[] original = {1,2,3};
        Document document = new Document(METADATA_TEST, original);
        byte[] tabReturned = document.content();
        tabReturned[0] = 99;
        assertArrayEquals(new byte[] {1, 2, 3}, document.content());


    }

    @Test
    void isTwoEqualsTablesAreEquals(){
        byte[] original1 = {1,2,3};
        byte[] original2 = {1,2,3};
        Document document1 = new Document(METADATA_TEST, original1);
        Document document2 = new Document(METADATA_TEST, original2);
        assertEquals(document1, document2);

    }

    @Test
    void toStringDoesNotRevealContent() {
        byte[] secret = "SECRET-CONTRAT".getBytes(StandardCharsets.UTF_8);
        Document document = new Document(METADATA_TEST, secret);

        String text = document.toString();

        assertFalse(text.contains("SECRET-CONTRAT"));
    }



}