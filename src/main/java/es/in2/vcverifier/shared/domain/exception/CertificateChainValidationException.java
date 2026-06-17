package es.in2.vcverifier.shared.domain.exception;

public class CertificateChainValidationException extends RuntimeException {

    public CertificateChainValidationException(String message) {
        super(message);
    }

    public CertificateChainValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
