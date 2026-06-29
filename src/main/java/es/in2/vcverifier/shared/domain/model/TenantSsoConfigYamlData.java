package es.in2.vcverifier.shared.domain.model;

import java.util.List;

/**
 * Domain model (port) for SSO configuration data loaded from YAML.
 * Represents the container for all tenant SSO configurations.
 */
public record TenantSsoConfigYamlData(List<TenantSsoEntry> tenants) {}

