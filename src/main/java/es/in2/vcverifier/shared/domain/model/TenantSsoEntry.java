package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * DTO de deserialización YAML para la configuración SSO de un tenant.
 * Todos los campos son opcionales en YAML excepto {@code tenant}.
 * {@code ttlAbsolute} y {@code ttlIdle} se expresan en formato ISO-8601
 * (p. ej. {@code "PT8H"}, {@code "PT30M"}); un valor ausente o mal formado
 * se trata como ausente y el adaptador aplica el default del sistema.
 */
public record TenantSsoEntry(
        String tenant,
        String rootDomain,
        boolean ssoEnabled,
        List<String> eligibleClients,
        String ttlAbsolute,
        String ttlIdle
) {}

