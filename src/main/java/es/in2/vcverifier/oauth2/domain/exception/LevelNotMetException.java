package es.in2.vcverifier.oauth2.domain.exception;

public class LevelNotMetException extends RuntimeException {
    public LevelNotMetException(String message) {
        super(message);
    }
}
