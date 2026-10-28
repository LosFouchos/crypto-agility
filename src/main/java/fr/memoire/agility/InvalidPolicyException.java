package fr.memoire.agility;

// Levée quand un fichier de politique est dangereux ou incohérent : il est refusé dès son chargement
public class InvalidPolicyException extends IllegalArgumentException {

    public InvalidPolicyException(String message) {
        super(message);
    }
}