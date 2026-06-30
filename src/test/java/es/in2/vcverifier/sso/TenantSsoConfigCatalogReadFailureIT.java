package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT: ES-02 — fail-safe del catálogo de clientes elegibles en TenantSsoConfigYamlAdapter.
 *
 * Garantías verificadas:
 *   Escenario A (init falla, sin config previa): resolveEligibleClients() devuelve
 *     TenantSsoCatalog.empty() — fail-closed, no hay nada que recuperar.
 *   Escenario B (refresh falla tras una carga previa válida): resolveEligibleClients()
 *     conserva el último catálogo válido gracias al AtomicReference, que sólo se
 *     actualiza si load() tiene éxito.
 *   Escenario C: log estructurado event=sso_config_refresh_failed /
 *     event=sso_config_init_failed emitido ante el fallo del provider.
 *   Escenario D: tras un fallo inicial, un refresh exitoso posterior sí actualiza el catálogo.
 *
 * Implementación: instanciación directa del adapter; provider controlado por
 * AtomicBoolean o lambda que lanza RuntimeException según el escenario.
 * No se necesita Spring ni Testcontainers.
 */
class TenantSsoConfigCatalogReadFailureIT {

    private ListAppender<ILoggingEvent> logCaptor;
    private Logger adapterLogger;

    @BeforeEach
    void attachLogCaptor() {
        adapterLogger = (Logger) LoggerFactory.getLogger(TenantSsoConfigYamlAdapter.class);
        logCaptor = new ListAppender<>();
        logCaptor.start();
        adapterLogger.addAppender(logCaptor);
    }

    @AfterEach
    void detachLogCaptor() {
        adapterLogger.detachAppender(logCaptor);
    }

    // =========================================================
    // Escenario A: init() falla sin config previa → catálogo vacío (fail-closed)
    // =========================================================

    @Test
    void resolveEligibleClients_returnsEmptyCatalog_whenInitFailsWithoutPriorConfig() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("IO error on startup"); }
        );
        adapter.init();   // debe absorber la excepción (no propagarla)

        TenantSsoCatalog catalog = adapter.resolveEligibleClients("any-tenant");

        // Fail-closed: sin config previa → catálogo vacío, ningún cliente es elegible
        assertThat(catalog.contains("any-client")).isFalse();
        assertThat(catalog).isEqualTo(TenantSsoCatalog.empty());
    }

    @Test
    void init_doesNotThrow_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("provider unavailable"); }
        );

        Assertions.assertDoesNotThrow(adapter::init);
    }

    // =========================================================
    // Escenario B: refresh() falla tras una carga válida previa →
    // se conserva el último catálogo válido (AtomicReference inalterado).
    // =========================================================

    @Test
    void resolveEligibleClients_retainsLastValidCatalog_whenRefreshFails() {
        AtomicBoolean shouldFail = new AtomicBoolean(false);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() -> {
            if (shouldFail.get()) {
                throw new RuntimeException("YAML file disappeared");
            }
            return new TenantSsoConfigYamlData(List.of(
                    new TenantSsoEntry("tenant-stable", "stable.example.com", true,
                            List.of("stable-client-1", "stable-client-2"), null, null)
            ));
        });
        adapter.init();

        // Verificamos que el catálogo se cargó correctamente
        TenantSsoCatalog beforeRefresh = adapter.resolveEligibleClients("tenant-stable");
        assertThat(beforeRefresh.contains("stable-client-1")).isTrue();
        assertThat(beforeRefresh.contains("stable-client-2")).isTrue();

        // El proveedor falla en el próximo ciclo de refresh
        shouldFail.set(true);
        adapter.refresh();   // debe absorber la excepción

        // El catálogo anterior se mantiene inalterado: el AtomicReference
        // no se actualiza cuando load() lanza una excepción.
        TenantSsoCatalog afterFailedRefresh = adapter.resolveEligibleClients("tenant-stable");
        assertThat(afterFailedRefresh.contains("stable-client-1")).isTrue();
        assertThat(afterFailedRefresh.contains("stable-client-2")).isTrue();
        assertThat(afterFailedRefresh).isEqualTo(beforeRefresh);
    }

    @Test
    void refresh_doesNotThrow_whenProviderFails() {
        TenantSsoConfigYamlAdapter failingAdapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("disk error"); }
        );
        failingAdapter.init();  // falla silenciosamente, cache vacío

        Assertions.assertDoesNotThrow(failingAdapter::refresh);
    }

    // =========================================================
    // Escenario C: logs estructurados ante fallo de init / refresh
    // =========================================================

    @Test
    void refresh_emitsStructuredLog_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("network timeout"); }
        );
        adapter.init();
        logCaptor.list.clear();   // limpiar el log emitido por el init fallido

        adapter.refresh();

        assertThat(logCaptor.list)
                .anyMatch(e -> e.getFormattedMessage().contains("event=sso_config_refresh_failed"))
                .anyMatch(e -> e.getFormattedMessage().contains("action=keeping_last_valid"));
    }

    @Test
    void init_emitsStructuredLog_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("config not found"); }
        );
        adapter.init();

        assertThat(logCaptor.list)
                .anyMatch(e -> e.getFormattedMessage().contains("event=sso_config_init_failed"));
    }

    // =========================================================
    // Escenario D: refresh exitoso tras un fallo previo → actualiza el catálogo
    // =========================================================

    @Test
    void resolveEligibleClients_updatesCatalog_whenRefreshSucceedsAfterPreviousFailure() {
        AtomicBoolean shouldFail = new AtomicBoolean(true);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() -> {
            if (shouldFail.get()) {
                throw new RuntimeException("first attempt fails");
            }
            return new TenantSsoConfigYamlData(List.of(
                    new TenantSsoEntry("tenant-r", "r.example.com", true,
                            List.of("recovered-client"), null, null)
            ));
        });

        adapter.init();   // falla → cache vacío → catálogo vacío (fail-closed)
        assertThat(adapter.resolveEligibleClients("tenant-r").contains("recovered-client")).isFalse();

        shouldFail.set(false);
        adapter.refresh();   // ahora tiene éxito → el catálogo se actualiza

        assertThat(adapter.resolveEligibleClients("tenant-r").contains("recovered-client")).isTrue();
    }
}
