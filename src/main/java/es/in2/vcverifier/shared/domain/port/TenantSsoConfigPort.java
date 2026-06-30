package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;

import java.util.Optional;

public interface TenantSsoConfigPort {


    Optional<TenantSsoConfig> getByTenant(String tenant);

    /**
     * Resuelve el TTL efectivo del tenant aplicando:
     * - defaults del sistema
     * - overrides del tenant si existen
     * - validación de rango
     * Devuelve objeto normalizado listo para uso en dominio SSO.
     */
    SsoSessionTtl resolveTtl(String tenant);

    /**
     * Resuelve el catálogo de clientes elegibles para reutilización SSO del tenant.
     * Catálogo vacío devuelve TenantSsoCatalog.empty() (fail-closed AC-03).
     */
    TenantSsoCatalog resolveEligibleClients(String tenant);
}
