package es.in2.vcverifier.shared.domain.port;


import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;

public interface TenantSsoConfigProvider {
    TenantSsoConfigYamlData retrieve();
}