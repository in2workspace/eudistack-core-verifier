package es.in2.vcverifier.verifier.domain.exception;

public class BumpedFormatTemporarilyDisabledException extends RuntimeException {

    public BumpedFormatTemporarilyDisabledException(String message) {
        super(message);
    }
}
