package es.in2.vcverifier.shared.domain.model;

import java.util.List;

/**
 * DTO de deserialización YAML para la configuración SSO de un tenant.
 * Todos los campos son opcionales en YAML excepto {@code tenant}.
 * {@code ttlAbsolute} y {@code ttlIdle} se expresan en formato ISO-8601
 * (p. ej. {@code "PT8H"}, {@code "PT30M"}); un valor ausente o mal formado
 * se trata como ausente y el adaptador aplica el default del sistema.
 * {@code eligibleClients} ausente en YAML desserializa a null; el constructor
 * compacto lo normaliza a lista vacía (lista nunca null, US-05).
 * <p>
 * US-06 (AD-4/DELTA-01): cada entrada de {@code eligibleClients} pasa de string plano a objeto
 * {@link EligibleClientConfig} (clientId + backchannelLogoutUri opcional). Shape YAML:
 * {@code - clientId: "app-a"} (opcionalmente {@code backchannelLogoutUri: "https://..."})
 * en lugar de {@code - "app-a"}.
 */
public record TenantSsoEntry(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        List<EligibleClientConfig> eligibleClients,
        String ttlAbsolute,
        String ttlIdle
) {
    public TenantSsoEntry {
        eligibleClients = eligibleClients != null ? eligibleClients : List.of();
    }
}

