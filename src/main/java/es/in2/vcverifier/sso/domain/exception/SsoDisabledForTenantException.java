package es.in2.vcverifier.sso.domain.exception;

public class SsoDisabledForTenantException extends RuntimeException {

    public SsoDisabledForTenantException(String tenantSlug) {
        super("SSO is disabled for tenant: " + tenantSlug);
    }
}
