package es.in2.vcverifier.oauth2.domain.exception;

public class IssuerNotTrustedException extends RuntimeException {

    public IssuerNotTrustedException(String message) {
        super(message);
    }

}
