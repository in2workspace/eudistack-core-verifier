package es.in2.vcverifier.sso.domain.exception;

public class SsoDisabledForTenantException extends RuntimeException {

    public SsoDisabledForTenantException(String message) {
        super(message);
    }
}
