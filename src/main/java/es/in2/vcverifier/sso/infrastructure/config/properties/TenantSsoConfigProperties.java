package es.in2.vcverifier.sso.infrastructure.config.properties;

import java.util.List;

/**
 * DTO de infraestructura para el binding Jackson del bloque per-tenant en sso-config.yaml.
 *
 * Campos TTL (US-04): {@code ttlAbsolute} / {@code ttlIdle} — ISO-8601, opcionales.
 * Campo catálogo (US-05): {@code eligibleClients} — lista de client_id; ausente ⇒ lista vacía.
 */
public record TenantSsoConfigProperties(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        String ttlAbsolute,
        String ttlIdle,
        List<String> eligibleClients
) {
    public TenantSsoConfigProperties {
        eligibleClients = eligibleClients != null ? List.copyOf(eligibleClients) : List.of();
    }
}
