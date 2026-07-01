package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.service.TenantSsoTtlPolicy;

import java.util.Optional;

public interface TenantSsoConfigPort {

    Optional<TenantSsoConfig> getByTenant(String tenant);

    /**
     * Resuelve el TTL efectivo para el tenant aplicando los rangos de ADR-106.
     * <p>
     * Delega la resolución por dimensión a {@link TenantSsoTtlPolicy#resolve}: si el
     * override almacenado en la configuración es válido para esa dimensión se usa; si no,
     * se aplica el valor por defecto del sistema (ver {@link es.in2.vcverifier.sso.domain.model.SsoTtlRange}).
     * Si el tenant no tiene configuración registrada devuelve {@link SsoSessionTtl#systemDefault()}.
     */
    default SsoSessionTtl resolveTtl(String tenant) {
        TenantSsoTtlPolicy policy = new TenantSsoTtlPolicy();
        return getByTenant(tenant)
                .map(config -> policy.resolve(config.ttl().absolute(), config.ttl().idle()))
                .orElseGet(SsoSessionTtl::systemDefault);
    }
}
