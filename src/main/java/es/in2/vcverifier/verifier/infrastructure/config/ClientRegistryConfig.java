package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry.LocalClientRegistryProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class ClientRegistryConfig {

    @Bean
    public ClientRegistryProvider localClientRegistryProvider(BackendConfig backendConfig) {
        log.info("Using Local Client Registry Provider (YAML)");
        return new LocalClientRegistryProvider(backendConfig.getLocalClientsPath());
    }
}
