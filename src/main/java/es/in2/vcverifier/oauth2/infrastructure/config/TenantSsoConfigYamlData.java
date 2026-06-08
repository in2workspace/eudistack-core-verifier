package es.in2.vcverifier.oauth2.infrastructure.config;

import java.util.List;

public record TenantSsoConfigYamlData(List<TenantSsoEntry> tenants) {}

