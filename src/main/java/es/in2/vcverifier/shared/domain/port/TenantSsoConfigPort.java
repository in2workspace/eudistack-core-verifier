package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;

import java.util.Optional;

public interface TenantSsoConfigPort {
    Optional<TenantSsoConfig> getByTenant(String tenant);
}
