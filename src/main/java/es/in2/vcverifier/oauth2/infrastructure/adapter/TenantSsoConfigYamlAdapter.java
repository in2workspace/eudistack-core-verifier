package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.service.TenantSsoTtlPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
@RequiredArgsConstructor
public class TenantSsoConfigYamlAdapter implements TenantSsoConfigPort {

    private final TenantSsoConfigProvider provider;

    // ES-02: AtomicReference retiene la última config válida.
    // refresh() sólo llama a cache.set() si load() tiene éxito;
    // ante cualquier excepción el cache permanece inalterado.
    private final AtomicReference<Map<String, TenantSsoConfig>> cache =
            new AtomicReference<>(new HashMap<>());

    private final TenantSsoTtlPolicy ttlPolicy = new TenantSsoTtlPolicy();

    @PostConstruct
    public void init() {
        try {
            cache.set(load());
            log.info("event=sso_config_init_ok tenants={}", cache.get().size());
        } catch (Exception e) {
            log.error("event=sso_config_init_failed action=starting_empty cause={}", e.getMessage());
        }
    }

    @Scheduled(cron = "${verifier.sso.configRefreshCron:0 */5 * * * ?}")
    public void refresh() {
        try {
            Map<String, TenantSsoConfig> fresh = load();
            cache.set(fresh);
            log.info("event=sso_config_refresh_ok tenants={}", fresh.size());
        } catch (Exception e) {
            // ES-02: fallo de lectura → se mantiene la última config válida del AtomicReference
            log.error("event=sso_config_refresh_failed action=keeping_last_valid cause={}", e.getMessage());
        }
    }

    @Override
    public Optional<TenantSsoConfig> getByTenant(String tenant) {
        if (tenant == null) return Optional.empty();
        return Optional.ofNullable(cache.get().get(tenant.toLowerCase()));
    }

    @Override
    public SsoSessionTtl resolveTtl(String tenant) {
        if (tenant == null) {
            return SsoSessionTtl.systemDefault();
        }
        TenantSsoConfig config = cache.get().get(tenant.toLowerCase());
        if (config == null) {
            return SsoSessionTtl.systemDefault();
        }
        return SsoSessionTtl.of(config.ttl().absolute(), config.ttl().idle());
    }

    private Map<String, TenantSsoConfig> load() {

        TenantSsoConfigYamlData yaml = provider.retrieve();

        Map<String, TenantSsoConfig> result = new HashMap<>();

        for (var t : yaml.tenants()) {

            String tenant = t.tenant() != null ? t.tenant().toLowerCase() : null;
            String rootDomain = t.rootDomain();
            boolean enabled = t.ssoEnabled();

            // ES-01: parseo aislado por tenant — valor malformado tratado como ausente
            Duration parsedAbsolute = parseDuration(t.ttlAbsolute(), tenant, "ttlAbsolute");
            Duration parsedIdle     = parseDuration(t.ttlIdle(),     tenant, "ttlIdle");

            // Delegar en TenantSsoTtlPolicy: null → default, fuera de rango → default + log
            SsoSessionTtl resolvedTtl = ttlPolicy.resolve(parsedAbsolute, parsedIdle);

            List<String> eligibleClients =
                    t.eligibleClients() != null ? t.eligibleClients() : List.of();

            if (enabled && (rootDomain == null || rootDomain.isBlank())) {

                result.put(tenant, new TenantSsoConfig(
                        tenant,
                        rootDomain,
                        false,
                        new TenantSsoConfig.SsoTtlConfig(
                                resolvedTtl.absolute(),
                                resolvedTtl.idle()
                        ),
                        eligibleClients
                ));

                log.error("event=sso_config_inconsistent tenant={} host={} correlation_id={}",
                        tenant, rootDomain, UUID.randomUUID());

                continue;
            }

            result.put(tenant, new TenantSsoConfig(
                    tenant,
                    rootDomain,
                    enabled,
                    new TenantSsoConfig.SsoTtlConfig(
                            resolvedTtl.absolute(),
                            resolvedTtl.idle()
                    ),
                    eligibleClients
            ));
        }

        return result;
    }

    /**
     * ES-01: parseo aislado por tenant.
     * null / blank → absent (devuelve null → TenantSsoTtlPolicy aplica default).
     * Valor malformado → log estructurado + null (aislamiento per-tenant).
     */
    private Duration parseDuration(String raw, String tenant, String field) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Duration.parse(raw);
        } catch (Exception e) {
            log.error("event=sso_ttl_parse_error tenant={} field={} value={} action=treating_as_absent",
                    tenant, field, raw);
            return null;
        }
    }
}
