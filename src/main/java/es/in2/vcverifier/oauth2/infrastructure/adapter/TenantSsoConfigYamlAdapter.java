package es.in2.vcverifier.oauth2.infrastructure.adapter;


import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
@RequiredArgsConstructor
public class TenantSsoConfigYamlAdapter implements TenantSsoConfigPort {

    private final TenantSsoConfigProvider provider;

    private final AtomicReference<Map<String, TenantSsoConfig>> cache =
            new AtomicReference<>(new HashMap<>());

    private static final Duration DEFAULT_ABSOLUTE_TTL = Duration.ofHours(8);
    private static final Duration DEFAULT_IDLE_TTL = Duration.ofMinutes(30);


    @PostConstruct
    public void init() {
        cache.set(load());
        log.info("Tenant SSO config initialized on startup");
    }

    /**
     * Se recarga el cron cada 5 minutos, guardando la configuracion en memoria (cache) de la lista de
     * tenant permitidos para poder acceder al SSO. Esto lo tenemos en el yaml de sso-config.yaml
     */
    @Scheduled(cron = "${verifier.sso.configRefreshCron:0 */5 * * * ?}")
    public void refresh() {
        try {
            cache.set(load());
        } catch (Exception e) {
            log.error("Failed to refresh tenant SSO config", e);
        }
    }

    @Override
    public Optional<TenantSsoConfig> getByTenant(String tenant) {
        // Normalización a lowercase para ser consistente con TenantDomainFilter
        // y evitar fallos con entradas YAML en mixedCase (e.g. "sandboxDos").
        if (tenant == null) return Optional.empty();
        return Optional.ofNullable(cache.get().get(tenant.toLowerCase()));
    }


    private Map<String, TenantSsoConfig> load() {

        TenantSsoConfigYamlData yaml = provider.retrieve();

        Map<String, TenantSsoConfig> result = new HashMap<>();

        for (var t : yaml.tenants()) {

            // Normalizamos el tenant a lowercase al cachear, para que las claves
            // sean consistentes con la normalización de TenantDomainFilter.
            String tenant = t.tenant() != null ? t.tenant().toLowerCase() : null;
            String rootDomain = t.rootDomain();
            boolean enabled = t.ssoEnabled();

            Duration absoluteTtl = DEFAULT_ABSOLUTE_TTL;
            Duration idleTtl = DEFAULT_IDLE_TTL;


            /** FAIL-CLOSED: Se incluye una validación de seguridad fail-closed:
             * si alguien configura ssoEnabled: true pero rootDomain está vacío, el sistema NO habilita el SSO
             * y emite un log estructurado con campos tenant, host, correlation_id y event sso_config_inconsistent.
             */
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

                log.error("event=sso_config_inconsistent tenant={} host={} correlation_id={}", tenant, rootDomain,
                        UUID.randomUUID());

                continue;
            }

            result.put(tenant, new TenantSsoConfig(tenant, rootDomain, enabled,
                    new TenantSsoConfig.SsoTtlConfig(
                            absoluteTtl,
                            idleTtl
                    )));
        }

        return result;
    }
}