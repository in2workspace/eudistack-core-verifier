package es.in2.vcverifier.verifier.infrastructure.adapter.config;

import es.in2.vcverifier.shared.config.properties.TenantDomeConfigProperties;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PropertiesTenantConfigAdapter implements TenantConfigPort {

    private final TenantDomeConfigProperties tenantDomeConfigProperties;

    @Override
    public TenantDomeConfig getDomeConfig(String tenantDomain) {
        return new TenantDomeConfig(
                tenantDomeConfigProperties.legacyReadEnabledOrDefault(),
                tenantDomeConfigProperties.bumpedReadEnabledOrDefault()
        );
    }
}
