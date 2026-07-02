package es.in2.vcverifier.sso.domain.exception;

/**
 * Lanzada cuando el client_id no figura en el catálogo SSO del tenant.
 * El workflow la captura y la mapea a error interaction_required (OID4VP / OIDC).
 */
public class SsoClientNotEligibleException extends RuntimeException {

    private final String tenant;
    private final String clientId;

    public SsoClientNotEligibleException(String tenant, String clientId) {
        super("Client '%s' is not eligible for SSO reuse in tenant '%s'".formatted(clientId, tenant));
        this.tenant = tenant;
        this.clientId = clientId;
    }

    public String tenant() {
        return tenant;
    }

    public String clientId() {
        return clientId;
    }
}
