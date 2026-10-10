package fr.memoire;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.NamedParameterSpec;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Java " + Runtime.version());

        // 1. Le destinataire génère une paire de clés ML-KEM-768
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
        kpg.initialize(NamedParameterSpec.ML_KEM_768);
        KeyPair destinataire = kpg.generateKeyPair();

        // 2. L'expéditeur utilise la clé publique pour "encapsuler" un secret
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulated resultat = kem.newEncapsulator(destinataire.getPublic()).encapsulate();
        SecretKey secretExpediteur = resultat.key();
        byte[] encapsulation = resultat.encapsulation(); // ce qui transite sur le réseau

        // 3. Le destinataire retrouve le même secret avec sa clé privée
        SecretKey secretDestinataire = kem.newDecapsulator(destinataire.getPrivate())
                .decapsulate(encapsulation);

        // 4. Vérifications
        boolean identiques = MessageDigest.isEqual(
                secretExpediteur.getEncoded(), secretDestinataire.getEncoded());

        System.out.println("Clé publique (encodée) : " + destinataire.getPublic().getEncoded().length + " octets");
        System.out.println("Encapsulation          : " + encapsulation.length + " octets");
        System.out.println("Secret partagé         : " + secretExpediteur.getEncoded().length + " octets");
        System.out.println("Secrets identiques ?   : " + identiques);
    }
}