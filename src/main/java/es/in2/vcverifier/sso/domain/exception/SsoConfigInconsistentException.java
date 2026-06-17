package es.in2.vcverifier.sso.domain.exception;

public class SsoConfigInconsistentException extends RuntimeException {

    public SsoConfigInconsistentException(String message, Throwable cause) {
        super(message, cause);
    }

    public SsoConfigInconsistentException(String message) {
        super(message);
    }
}
