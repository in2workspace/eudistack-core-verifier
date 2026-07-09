package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;

/**
 * Port (SPI) for retrieving and updating SSO tenant configurations.
 * Implementations should load configurations from YAML or other sources.
 * Returns domain model {@link TenantSsoConfigYamlData}.
 */
public interface TenantSsoConfigProvider {
    TenantSsoConfigYamlData retrieve();

    /**
     * Añade un cliente elegible al catálogo SSO del tenant en la fuente de config.
     * Idempotente: devuelve {@code false} si el cliente ya estaba presente.
     */
    boolean addEligibleClient(String tenant, String clientId);

    /**
     * Elimina un cliente elegible del catálogo SSO del tenant en la fuente de config.
     * Idempotente: devuelve {@code false} si el cliente no estaba presente.
     */
    boolean removeEligibleClient(String tenant, String clientId);
}