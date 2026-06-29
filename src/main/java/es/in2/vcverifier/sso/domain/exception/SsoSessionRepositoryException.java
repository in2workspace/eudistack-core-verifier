package es.in2.vcverifier.sso.domain.exception;

public class SsoSessionRepositoryException extends RuntimeException {

    public SsoSessionRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }

    public SsoSessionRepositoryException(String message) {
        super(message);
    }
}
