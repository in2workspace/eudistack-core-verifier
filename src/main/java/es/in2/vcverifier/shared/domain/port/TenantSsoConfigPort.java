package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;

import java.util.Optional;

public interface TenantSsoConfigPort {

    Optional<TenantSsoConfig> getByTenant(String tenant);

    /**
     * Resuelve el TTL efectivo para el tenant aplicando los rangos de ADR-106.
     * Si el tenant no tiene configuración registrada devuelve {@link SsoSessionTtl#systemDefault()}.
     * Implementado en {@code TenantSsoConfigYamlAdapter}.
     */
    SsoSessionTtl resolveTtl(String tenant);

    /**
     * Resuelve el catálogo de clientes elegibles para SSO del tenant.
     * AC-03 fail-closed: devuelve {@link TenantSsoCatalog#empty()} si el tenant no existe
     * o no tiene clientes configurados.
     */
    TenantSsoCatalog resolveEligibleClients(String tenant);
}
