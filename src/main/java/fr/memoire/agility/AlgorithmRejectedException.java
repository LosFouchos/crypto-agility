package fr.memoire.agility;

import java.security.GeneralSecurityException;

// quand la politique refuse un algorithme pour une opération (écriture ou lecture)
public class AlgorithmRejectedException extends GeneralSecurityException {

    public AlgorithmRejectedException(String message) {
        super(message);
    }
}