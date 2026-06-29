package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Domain model (port) for SSO tenant configuration entry.
 * Represents a single tenant's SSO settings from YAML.
 */
public record TenantSsoEntry(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        List<String> eligibleClients,
        // ISO-8601 optionals — null means "use system default"
        String ttlAbsolute,
        String ttlIdle
) {}

