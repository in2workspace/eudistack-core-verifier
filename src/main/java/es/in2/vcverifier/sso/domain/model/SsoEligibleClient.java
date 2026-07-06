package es.in2.vcverifier.sso.domain.model;

/**
 * Value object que identifica un cliente elegible para SSO.
 * EC-04: punto único de normalización — trim aplicado en el constructor compacto;
 * sin transformación de caja para preservar el client_id tal como lo registra el IdP.
 */
public record SsoEligibleClient(String clientId) {

    public SsoEligibleClient {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("SsoEligibleClient.clientId must not be blank");
        }
        clientId = clientId.trim();
    }

    public static SsoEligibleClient of(String clientId) {
        return new SsoEligibleClient(clientId);
    }
}
