package es.in2.vcverifier.shared.domain.model;

import java.time.Duration;
import java.util.List;

public record TenantSsoConfig(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        SsoTtlConfig ttl,

        // lista de clientes elegibles para reutilización SSO
        List<String> eligibleClientIds
) {

    public record SsoTtlConfig(
            Duration absolute,
            Duration idle
    ) {}
}