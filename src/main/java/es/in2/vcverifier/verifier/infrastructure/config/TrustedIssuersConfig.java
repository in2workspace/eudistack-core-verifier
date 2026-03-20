package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import es.in2.vcverifier.verifier.infrastructure.adapter.trustframework.LocalTrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class TrustedIssuersConfig {

    @Bean
    public TrustedIssuersProvider localTrustedIssuersProvider(BackendConfig backendConfig) {
        log.info("Using Local Trusted Issuers Provider (YAML)");
        return new LocalTrustedIssuersProvider(backendConfig.getLocalTrustedIssuersPath());
    }
}
