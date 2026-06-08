package es.in2.vcverifier.shared.domain.model;

public record TenantSsoConfig(
        String tenant,
        String rootDomain,
        boolean ssoEnabled
) {}
