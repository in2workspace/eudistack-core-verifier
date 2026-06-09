package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
public class TenantSsoConfigYamlAdapter implements TenantSsoConfigPort {

    private final TenantSsoConfigProvider provider;

    private final AtomicReference<Map<String, TenantSsoConfig>> cache =
            new AtomicReference<>(new HashMap<>());

    private static final Duration DEFAULT_ABSOLUTE_TTL = Duration.ofHours(8);
    private static final Duration DEFAULT_IDLE_TTL = Duration.ofMinutes(30);


    public TenantSsoConfigYamlAdapter(
            TenantSsoConfigProvider provider
    ) {
        this.provider = provider;
    }

    @Scheduled(cron = "${verifier.sso.configRefreshCron:0 */5 * * * ?}")
    public void refresh() {
        try {
            log.info("Refreshing tenant SSO config...");
            cache.set(load());
            log.info("Tenant SSO config refreshed successfully");
        } catch (Exception e) {
            log.error("Failed to refresh tenant SSO config", e);
        }
    }

    @Override
    public Optional<TenantSsoConfig> getByTenant(String tenant) {
        return Optional.ofNullable(cache.get().get(tenant));
    }

    private Map<String, TenantSsoConfig> load() {

        TenantSsoConfigYamlData yaml = provider.retrieve();

        Map<String, TenantSsoConfig> result = new HashMap<>();

        for (var t : yaml.tenants()) {

            String tenant = t.tenant();
            String rootDomain = t.rootDomain();
            boolean enabled = Boolean.TRUE.equals(t.ssoEnabled());

            Duration absoluteTtl = DEFAULT_ABSOLUTE_TTL;
            Duration idleTtl = DEFAULT_IDLE_TTL;

            if (enabled && (rootDomain == null || rootDomain.isBlank())) {

                result.put(tenant, new TenantSsoConfig(
                        tenant,
                        rootDomain,
                        false,
                        new TenantSsoConfig.SsoTtlConfig(
                                DEFAULT_ABSOLUTE_TTL,
                                DEFAULT_IDLE_TTL
                        )
                ));

                log.error(
                        "event=sso_config_inconsistent tenant={} host={} correlation_id={}",
                        tenant,
                        "unknown",
                        UUID.randomUUID()
                );

                continue;
            }

            result.put(tenant, new TenantSsoConfig(
                    tenant,
                    rootDomain,
                    enabled,
                    new TenantSsoConfig.SsoTtlConfig(
                            absoluteTtl,
                            idleTtl
                    )
            ));
        }

        return result;
    }
}