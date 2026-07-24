package es.in2.vcverifier.shared.domain.model;

import java.time.Duration;
import java.util.List;

public record TenantSsoConfig(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        SsoTtlConfig ttl,

        // Catálogo de clientes elegibles para reutilización SSO (US-05) enriquecido con
        // backchannelLogoutUri opcional (US-06, AD-4/DELTA-01 fallback source).
        // Reemplaza el antiguo eligibleClientIds: List<String>.
        List<EligibleClientConfig> eligibleClients
) {

    public record SsoTtlConfig(
            Duration absolute,
            Duration idle
    ) {}
}