package es.in2.vcverifier.oauth2.infrastructure.adapter;


import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

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

    /**
     * Se recarga el cron cada 5 minutos, guardando la configuracion en memoria (cache) de la lista de
     * tenant permitidos para poder acceder al SSO. Esto lo tenemos en el yaml de sso-config.yaml
     */
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

        es.in2.vcverifier.shared.domain.port.TenantSsoConfigYamlData yaml = provider.retrieve();

        Map<String, TenantSsoConfig> result = new HashMap<>();

        for (var t : yaml.tenants()) {

            // Variables cargadas con los valores del sso-config.yaml
            String tenant = t.tenant();
            String rootDomain = t.rootDomain();
            boolean enabled = Boolean.TRUE.equals(t.ssoEnabled());


            /** 🔒 FAIL-CLOSED -> Se incluye una validación de seguridad fail-closed:
             * si alguien configura sso.enabled: true pero rootDomain está vacío, el sistema NO habilita el SSO
             * y emite un log estructurado con campos tenant, host, correlation_id y event sso_config_inconsistent.
             */
            if (enabled && (rootDomain == null || rootDomain.isBlank())) {

                result.put(tenant, new TenantSsoConfig(
                        tenant,
                        rootDomain,
                        false
                ));

                // Informamos del error por consola.
                log.error("event=sso_config_inconsistent tenant={} host={} correlation_id={}", tenant, "unknown",
                        UUID.randomUUID());

                continue;
            }

            // Devolvemos el resultado
            result.put(tenant, new TenantSsoConfig(tenant, rootDomain, enabled));
        }

        return result;
    }
}