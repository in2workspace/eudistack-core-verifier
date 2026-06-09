package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Domain model (port) for SSO tenant configuration entry.
 * Represents a single tenant's SSO settings from YAML.
 */
public record TenantSsoEntry(
        String tenant,
        String rootDomain,
        @JsonProperty("sso.enabled")
        Boolean ssoEnabled
) {}

