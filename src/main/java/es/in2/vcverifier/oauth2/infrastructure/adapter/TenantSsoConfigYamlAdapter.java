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
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
@RequiredArgsConstructor
public class TenantSsoConfigYamlAdapter implements TenantSsoConfigPort {

    private final TenantSsoConfigProvider provider;

    private final AtomicReference<Map<String, TenantSsoConfig>> cache =
            new AtomicReference<>(new HashMap<>());

    private static final TenantSsoTtlPolicy TTL_POLICY = new TenantSsoTtlPolicy();

    @PostConstruct
    public void init() {
        cache.set(load());
        log.info("Tenant SSO config initialized on startup");
    }

    /**
     * ES-02 — fail-safe a última config válida:
     * si {@code load()} lanza, la excepción se captura y {@code cache} no se actualiza,
     * preservando la última configuración cargada correctamente.
     */
    @Scheduled(cron = "${verifier.sso.configRefreshCron:0 */5 * * * ?}")
    public void refresh() {
        try {
            cache.set(load());
        } catch (Exception e) {
            log.error("event=sso_config_refresh_failed — retaining last valid config", e);
        }
    }

    @Override
    public Optional<TenantSsoConfig> getByTenant(String tenant) {
        if (tenant == null) return Optional.empty();
        return Optional.ofNullable(cache.get().get(tenant.toLowerCase()));
    }

    private Map<String, TenantSsoConfig> load() {

        TenantSsoConfigYamlData yaml = provider.retrieve();

        Map<String, TenantSsoConfig> result = new HashMap<>();

        for (var t : yaml.tenants()) {

            String tenant = t.tenant() != null ? t.tenant().toLowerCase() : null;
            String rootDomain = t.rootDomain();
            boolean enabled = t.ssoEnabled();

            // ES-01 — valor mal formado tratado como ausente: log estructurado por dimensión
            Duration parsedAbsolute = parseDuration(t.ttlAbsolute(), tenant, "ttlAbsolute");
            Duration parsedIdle     = parseDuration(t.ttlIdle(),     tenant, "ttlIdle");

            // Delegamos al servicio de dominio: override-si-válido-else-default por dimensión
            SsoSessionTtl ttl = TTL_POLICY.resolve(parsedAbsolute, parsedIdle);

            List<String> eligibleClients =
                    t.eligibleClients() != null ? t.eligibleClients() : List.of();

            // FAIL-CLOSED: ssoEnabled=true pero rootDomain ausente → SSO desactivado
            if (enabled && (rootDomain == null || rootDomain.isBlank())) {

                result.put(tenant, new TenantSsoConfig(
                        tenant,
                        rootDomain,
                        false,
                        new TenantSsoConfig.SsoTtlConfig(ttl.absolute(), ttl.idle()),
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
                    new TenantSsoConfig.SsoTtlConfig(ttl.absolute(), ttl.idle()),
                    eligibleClients
            ));
        }

        return result;
    }

    /**
     * ES-01 — parseo defensivo de duración ISO-8601.
     * Un valor ausente ({@code null}/blank) o mal formado se trata como ausente:
     * se registra un aviso estructurado y se devuelve {@code null} para que el
     * servicio de dominio aplique el default de sistema.
     */
    private static Duration parseDuration(String value, String tenant, String field) {
        if (value == null || value.isBlank()) return null;
        try {
            return Duration.parse(value);
        } catch (DateTimeParseException ex) {
            log.warn("event=sso_ttl_malformed tenant={} field={} value={} — treating as absent",
                    tenant, field, value);
            return null;
        }
    }
}