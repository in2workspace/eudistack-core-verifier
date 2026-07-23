package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
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
public class TenantSsoConfigYamlAdapter implements TenantSsoConfigPort, SsoCatalogRepositoryPort {

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
    public SsoSessionTtl resolveTtl(String tenant) {
        return getByTenant(tenant)
                .filter(config -> config.ttl() != null)
                .map(config -> TTL_POLICY.resolve(config.ttl().absolute(), config.ttl().idle()))
                .orElseGet(SsoSessionTtl::systemDefault);
    }

    @Override
    public Optional<TenantSsoConfig> getByTenant(String tenant) {
        if (tenant == null) return Optional.empty();
        return Optional.ofNullable(cache.get().get(tenant.toLowerCase()));
    }

    @Override
    public TenantSsoCatalog resolveEligibleClients(String tenant) {
        return getByTenant(tenant)
                .map(config -> {
                    List<SsoEligibleClient> clients = config.eligibleClients().stream()
                            .map(e -> SsoEligibleClient.of(e.clientId(), e.backchannelLogoutUri()))
                            .toList();
                    return TenantSsoCatalog.of(clients);
                })
                .orElseGet(TenantSsoCatalog::empty);
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

            // ES-01 — parseo defensivo por entrada: mal-formadas descartadas individualmente,
            // no todo el catálogo; aislamiento per-tenant (fallo de un tenant no aborta otros).
            // ES-02 — el AtomicReference + @Scheduled preserva última config válida si load() lanza;
            // resolveEligibleClients() devuelve TenantSsoCatalog.empty() si el tenant no tiene config.
            List<EligibleClientConfig> eligibleClients = parseEligibleClients(tenant, t.eligibleClients());

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

    // =========================================================
    // SsoCatalogRepositoryPort — AD-1: escritura sobre YAML/EFS
    // =========================================================

    /**
     * AC-04: alta idempotente de un cliente en el catálogo del tenant.
     * Delega la escritura al provider (YAML/EFS) y refresca el caché en memoria.
     */
    @Override
    public boolean addClient(String tenant, SsoEligibleClient client) {
        boolean added = provider.addEligibleClient(tenant, client.clientId());
        cache.set(load());
        return added;
    }

    /**
     * AC-04: baja idempotente de un cliente del catálogo del tenant.
     * Delega la escritura al provider (YAML/EFS) y refresca el caché en memoria.
     */
    @Override
    public boolean removeClient(String tenant, SsoEligibleClient client) {
        boolean removed = provider.removeEligibleClient(tenant, client.clientId());
        cache.set(load());
        return removed;
    }

    /**
     * ES-01 — parseo defensivo de la lista de {@code eligibleClients}.
     * Cada entrada se evalúa de forma independiente: una entrada nula, con {@code clientId} en
     * blanco, o que lance al construir {@link SsoEligibleClient} se descarta con log estructurado,
     * sin afectar al resto de entradas del tenant ni al refresco de otros tenants.
     * Si la lista de entrada es {@code null} se devuelve catálogo vacío (fail-closed ES-02).
     * <p>
     * US-06 (AD-4/DELTA-01): cada entrada es {@link EligibleClientConfig} (clientId +
     * backchannelLogoutUri opcional), no un string plano.
     */
    private static List<EligibleClientConfig> parseEligibleClients(String tenant, List<EligibleClientConfig> raw) {
        if (raw == null) return List.of();
        List<EligibleClientConfig> valid = new ArrayList<>(raw.size());
        for (EligibleClientConfig entry : raw) {
            if (entry == null || entry.clientId() == null || entry.clientId().isBlank()) {
                log.warn("event=sso_catalog_entry_malformed tenant={} entry=null_or_blank — discarding",
                        tenant);
                continue;
            }
            try {
                // SsoEligibleClient.of aplica trim y valida; su valor normalizado es el canónico.
                SsoEligibleClient normalized = SsoEligibleClient.of(entry.clientId(), entry.backchannelLogoutUri());
                valid.add(EligibleClientConfig.of(normalized.clientId(), normalized.backchannelLogoutUri()));
            } catch (IllegalArgumentException ex) {
                log.warn("event=sso_catalog_entry_malformed tenant={} entry=\"{}\" — discarding: {}",
                        tenant, entry.clientId(), ex.getMessage());
            }
        }
        return List.copyOf(valid);
    }
}