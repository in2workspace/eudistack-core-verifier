package es.in2.vcverifier.oauth2.domain.exception;

public class TenantMismatchException extends RuntimeException {

    public TenantMismatchException(String message) {
        super(message);
    }

}
