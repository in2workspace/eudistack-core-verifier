package es.in2.vcverifier.sso.domain.exception;

public class SsoCatalogRepositoryException extends RuntimeException {

    public SsoCatalogRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }

    public SsoCatalogRepositoryException(String message) {
        super(message);
    }
}
