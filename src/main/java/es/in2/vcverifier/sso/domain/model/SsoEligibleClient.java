package es.in2.vcverifier.sso.domain.model;

import java.util.Objects;

/**
 * Value object que identifica un cliente elegible para SSO.
 * EC-04: punto único de normalización — trim aplicado en el constructor;
 * sin transformación de caja para preservar el client_id tal como lo registra el IdP.
 * <p>
 * US-06 (AD-4/DELTA-01): incorpora {@code backchannelLogoutUri} opcional (fallback source para
 * el Back-Channel Logout cuando el RP no lo declara vía {@code ClientSettings}). Clase (no record):
 * {@code equals}/{@code hashCode} se definen por identidad de {@code clientId} únicamente —
 * {@link TenantSsoCatalog} usa un {@code Set<SsoEligibleClient>} para membership testing
 * (¿está este client_id en el catálogo?), no para comparar el valor completo de la URI.
 */
public final class SsoEligibleClient {

    private final String clientId;
    private final String backchannelLogoutUri;

    private SsoEligibleClient(String clientId, String backchannelLogoutUri) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("SsoEligibleClient.clientId must not be blank");
        }
        this.clientId = clientId.trim();
        this.backchannelLogoutUri = backchannelLogoutUri;
    }

    public static SsoEligibleClient of(String clientId) {
        return new SsoEligibleClient(clientId, null);
    }

    public static SsoEligibleClient of(String clientId, String backchannelLogoutUri) {
        return new SsoEligibleClient(clientId, backchannelLogoutUri);
    }

    public String clientId() {
        return clientId;
    }

    public String backchannelLogoutUri() {
        return backchannelLogoutUri;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SsoEligibleClient that)) return false;
        return clientId.equals(that.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }

    @Override
    public String toString() {
        return "SsoEligibleClient{clientId='" + clientId + "', backchannelLogoutUri='" + backchannelLogoutUri + "'}";
    }
}
