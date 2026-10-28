package fr.memoire.corpus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;


public final class KeyFiles {

    private KeyFiles() { }

    public static void save(KeyPair keyPair, Path directory, String name) throws IOException {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(directory, "Directory cannot be null");
        Objects.requireNonNull(name, "Name cannot be null");

        Files.write(directory.resolve(name + ".pub"), keyPair.getPublic().getEncoded(),
                StandardOpenOption.CREATE_NEW);
        Files.write(directory.resolve(name + ".key"), keyPair.getPrivate().getEncoded(),
                StandardOpenOption.CREATE_NEW);
    }

    public static KeyPair load(Path directory, String name, String algorithm)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(directory, "Directory cannot be null");
        Objects.requireNonNull(name, "Name cannot be null");
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");

        KeyFactory factory = KeyFactory.getInstance(algorithm);
        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(directory.resolve(name + ".pub"))));
        PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve(name + ".key"))));
        return new KeyPair(publicKey, privateKey);
    }
}