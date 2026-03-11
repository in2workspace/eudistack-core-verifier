package es.in2.vcverifier.shared.domain.exception;

public class SsrfProtectionException extends RuntimeException {

    public SsrfProtectionException(String message) {
        super(message);
    }

}