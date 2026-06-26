package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;

public interface TenantConfigPort {
    TenantDomeConfig getDomeConfig(String tenantDomain);
}
