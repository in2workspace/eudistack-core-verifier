package es.in2.vcverifier.sso.domain.exception;

public class SsoClientNotEligibleException extends RuntimeException {

    private final String tenant;
    private final String clientId;

    public SsoClientNotEligibleException(String tenant, String clientId) {
        super("Client not eligible for SSO reuse: tenant=" + tenant + ", clientId=" + clientId);
        this.tenant = tenant;
        this.clientId = clientId;
    }

    public SsoClientNotEligibleException(String tenant, String clientId, Throwable cause) {
        super("Client not eligible for SSO reuse: tenant=" + tenant + ", clientId=" + clientId, cause);
        this.tenant = tenant;
        this.clientId = clientId;
    }

    public String getTenant() {
        return tenant;
    }

    public String getClientId() {
        return clientId;
    }
}
