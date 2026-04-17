package es.in2.vcverifier.verifier.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import es.in2.vcverifier.verifier.infrastructure.adapter.trustframework.EbsiV4TrustedIssuersProvider;
import es.in2.vcverifier.verifier.infrastructure.adapter.trustframework.LocalTrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;

import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;

import java.net.http.HttpClient;

@Slf4j
@Configuration
public class TrustedIssuersConfig {

    private final ObjectProvider<TrustedIssuersProvider> trustedIssuersProviderRef;

    public TrustedIssuersConfig(ObjectProvider<TrustedIssuersProvider> trustedIssuersProviderRef) {
        this.trustedIssuersProviderRef = trustedIssuersProviderRef;
    }

    @Bean
    @ConditionalOnProperty(name = "verifier.backend.trustFrameworks[0].trustedIssuersListUrl")
    public TrustedIssuersProvider ebsiV4TrustedIssuersProvider(BackendConfig backendConfig, ObjectMapper objectMapper, HttpClient httpClient, SafeUrlValidator safeUrlValidator) {
        log.info("Using EBSI v4 Trusted Issuers Provider (remote)");
        return new EbsiV4TrustedIssuersProvider(backendConfig, objectMapper, httpClient, safeUrlValidator);
    }

    @Bean
    @ConditionalOnMissingBean(TrustedIssuersProvider.class)
    public TrustedIssuersProvider localTrustedIssuersProvider(BackendConfig backendConfig) {
        log.info("Using Local Trusted Issuers Provider (YAML)");
        return new LocalTrustedIssuersProvider(backendConfig.getLocalTrustedIssuersPath());
    }

    @Scheduled(cron = "${verifier.backend.trustedIssuersRefreshCron:0 */5 * * * ?}")
    public void refreshTrustedIssuers() {
        TrustedIssuersProvider provider = trustedIssuersProviderRef.getIfAvailable();
        if (provider instanceof LocalTrustedIssuersProvider localProvider) {
            try {
                log.info("Refreshing trusted issuers list...");
                localProvider.refresh();
                log.info("Trusted issuers list refreshed successfully");
            } catch (Exception e) {
                log.error("Failed to refresh trusted issuers list, keeping previous version", e);
            }
        }
    }
}
