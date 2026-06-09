package es.in2.vcverifier.oauth2.domain.exception;

public class SsoConfigLoadingException extends RuntimeException {

    public SsoConfigLoadingException(String message) {
        super(message);
    }

    public SsoConfigLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
