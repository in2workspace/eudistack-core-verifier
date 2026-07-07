package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Entrada del catálogo de aplicativos elegibles para SSO de un tenant (US-05),
 * enriquecida con {@code backchannelLogoutUri} (US-06, AD-4/DELTA-01 fallback source).
 * Reutilizada tanto como DTO de deserialización YAML ({@code TenantSsoEntry.eligibleClients})
 * como en el modelo de dominio compartido ({@code TenantSsoConfig.eligibleClients}) — no hay
 * lógica de validación embebida que justifique tipos separados (US-05 mantuvo el mismo criterio
 * con la lista plana de client_ids).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record EligibleClientConfig(String clientId, String backchannelLogoutUri) {

    public static EligibleClientConfig of(String clientId) {
        return new EligibleClientConfig(clientId, null);
    }

    public static EligibleClientConfig of(String clientId, String backchannelLogoutUri) {
        return new EligibleClientConfig(clientId, backchannelLogoutUri);
    }
}
