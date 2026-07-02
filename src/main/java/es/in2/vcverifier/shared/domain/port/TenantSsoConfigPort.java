package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;

import java.util.Optional;

public interface TenantSsoConfigPort {

    Optional<TenantSsoConfig> getByTenant(String tenant);

    /**
     * Resuelve el TTL efectivo para el tenant aplicando los rangos de ADR-106.
     * Si el tenant no tiene configuración registrada devuelve {@link SsoSessionTtl#systemDefault()}.
     * Implementado en {@code TenantSsoConfigYamlAdapter}.
     */
    SsoSessionTtl resolveTtl(String tenant);
}
