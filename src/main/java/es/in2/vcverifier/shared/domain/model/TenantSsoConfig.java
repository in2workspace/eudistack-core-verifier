package es.in2.vcverifier.shared.domain.model;

import java.time.Duration;

public record TenantSsoConfig(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        SsoTtlConfig ttl
) {

    public record SsoTtlConfig(
            Duration absolute,
            Duration idle
    ) {}
}