package fr.memoire;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

public class SignatureDemo {

    public static void main(String[] args) throws Exception {
        tester("ECDSA P-256 (classique)", "EC", new ECGenParameterSpec("secp256r1"), "SHA256withECDSA");
        tester("ML-DSA-65 (post-quantique)", "ML-DSA", NamedParameterSpec.ML_DSA_65, "ML-DSA");
    }

    static void tester(String titre, String algoCle, AlgorithmParameterSpec params, String algoSignature)
            throws Exception {
        byte[] contrat = "Contrat n°42 : montant 10 000 EUR".getBytes(StandardCharsets.UTF_8);

        // 1. Générer la paire de clés
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoCle);
        kpg.initialize(params);
        KeyPair kp = kpg.generateKeyPair();

        // 2. Signer avec la clé privée
        Signature signataire = Signature.getInstance(algoSignature);
        signataire.initSign(kp.getPrivate());
        signataire.update(contrat);
        byte[] signature = signataire.sign();

        // 3. Vérifier avec la clé publique
        Signature verificateur = Signature.getInstance(algoSignature);
        verificateur.initVerify(kp.getPublic());
        verificateur.update(contrat);
        boolean valide = verificateur.verify(signature);

        // 4. Falsifier le contrat et revérifier
        byte[] falsifie = "Contrat n°42 : montant 90 000 EUR".getBytes(StandardCharsets.UTF_8);
        verificateur.initVerify(kp.getPublic());
        verificateur.update(falsifie);
        boolean valideApresFalsification = verificateur.verify(signature);

        System.out.println("=== " + titre + " ===");
        System.out.println("Clé publique (encodée)    : " + kp.getPublic().getEncoded().length + " octets");
        System.out.println("Signature                 : " + signature.length + " octets");
        System.out.println("Signature valide ?        : " + valide);
        System.out.println("Valide après falsification: " + valideApresFalsification);
        System.out.println();
    }
}