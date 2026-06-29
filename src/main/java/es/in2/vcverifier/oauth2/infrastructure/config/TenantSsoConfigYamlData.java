package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;

import java.util.List;

public record TenantSsoConfigYamlData(List<TenantSsoEntry> tenants) {}

