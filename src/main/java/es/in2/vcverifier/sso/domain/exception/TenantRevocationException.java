package es.in2.vcverifier.sso.domain.exception;

public class TenantRevocationException extends RuntimeException {

    private final String correlationId;

    public TenantRevocationException(String message, Throwable cause, String correlationId) {
        super(message, cause);
        this.correlationId = correlationId;
    }

    public TenantRevocationException(String message, Throwable cause) {
        this(message, cause, null);
    }

    public TenantRevocationException(String message) {
        this(message, null, null);
    }

    public String getCorrelationId() {
        return correlationId;
    }
}
