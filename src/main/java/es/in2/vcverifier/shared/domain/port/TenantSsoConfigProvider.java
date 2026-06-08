package es.in2.vcverifier.shared.domain.port;

/**
 * Port (SPI) for retrieving SSO tenant configurations.
 * Implementations should load configurations from YAML or other sources.
 * Returns domain model {@link TenantSsoConfigYamlData}.
 */
public interface TenantSsoConfigProvider {
    TenantSsoConfigYamlData retrieve();
}