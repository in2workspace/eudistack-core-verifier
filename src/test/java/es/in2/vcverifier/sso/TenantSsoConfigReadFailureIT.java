package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import org.junit.jupiter.api.Assertions;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT: ES-02 — fail-safe de TenantSsoConfigYamlAdapter.
 *
 * Garantías verificadas:
 *   Escenario A (init falla): resolveTtl() devuelve system defaults (cache vacío).
 *   Escenario B (refresh falla): resolveTtl() conserva la última config válida,
 *     no revierte a defaults ni lanza excepción.
 *   Escenario C: log estructurado event=sso_config_refresh_failed emitido en refresh fallido.
 *
 * Implementación: instanciación directa del adapter; provider controlado por un
 * AtomicBoolean o un lambda que lanza RuntimeException según el escenario.
 */
class TenantSsoConfigReadFailureIT {

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
    // Escenario A: init() falla → cache vacío → system defaults
    // =========================================================

    @Test
    void resolveTtl_returnsSystemDefaults_whenInitFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("IO error on startup"); }
        );
        adapter.init();   // debe absorber la excepción (no propagarla)

        SsoSessionTtl ttl = adapter.resolveTtl("any-tenant");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    @Test
    void init_doesNotThrow_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("provider unavailable"); }
        );

        // No debe lanzar ninguna excepción
        Assertions.assertDoesNotThrow(adapter::init);
    }

    // =========================================================
    // Escenario B: refresh() falla → se conserva la última config válida
    // =========================================================

    @Test
    void resolveTtl_retainsLastValidConfig_whenRefreshFails() {
        // Paso 1: init() exitoso con un tenant válido
        AtomicBoolean shouldFail = new AtomicBoolean(false);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() -> {
            if (shouldFail.get()) {
                throw new RuntimeException("YAML file disappeared");
            }
            return new TenantSsoConfigYamlData(List.of(
                    new TenantSsoEntry("tenant-stable", "stable.example.com", true,
                            List.of(), "PT6H", "PT20M")
            ));
        });
        adapter.init();

        // Verificamos que la config se cargó correctamente
        SsoSessionTtl beforeRefresh = adapter.resolveTtl("tenant-stable");
        assertThat(beforeRefresh.absolute()).isEqualTo(Duration.ofHours(6));
        assertThat(beforeRefresh.idle()).isEqualTo(Duration.ofMinutes(20));

        // Paso 2: el proveedor falla en el próximo refresh
        shouldFail.set(true);
        adapter.refresh();   // debe absorber la excepción

        // Paso 3: la config anterior se mantiene inalterada
        SsoSessionTtl afterFailedRefresh = adapter.resolveTtl("tenant-stable");
        assertThat(afterFailedRefresh.absolute()).isEqualTo(Duration.ofHours(6));
        assertThat(afterFailedRefresh.idle()).isEqualTo(Duration.ofMinutes(20));
    }

    @Test
    void refresh_doesNotThrow_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> new TenantSsoConfigYamlData(List.of())
        );
        adapter.init();

        // Cambiamos el provider a uno que falla en el siguiente ciclo
        // Reutilizamos un adapter ya inicializado con config vacía, luego forzamos
        // fallo via un adapter nuevo cuyo provider siempre lanza
        TenantSsoConfigYamlAdapter failingAdapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("disk error"); }
        );
        failingAdapter.init();  // falla silenciosamente

        Assertions.assertDoesNotThrow(failingAdapter::refresh);
    }

    // =========================================================
    // Escenario C: log estructurado en refresh fallido
    // =========================================================

    @Test
    void refresh_emitsStructuredLog_whenProviderFails() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(
                () -> { throw new RuntimeException("network timeout"); }
        );
        adapter.init();
        logCaptor.list.clear();  // limpiar el log del init fallido

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
    // Escenario D: refresh exitoso tras un fallo previo → actualiza config
    // =========================================================

    @Test
    void resolveTtl_updatesConfig_whenRefreshSucceedsAfterPreviousFailure() {
        AtomicBoolean shouldFail = new AtomicBoolean(true);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() -> {
            if (shouldFail.get()) {
                throw new RuntimeException("first attempt fails");
            }
            return new TenantSsoConfigYamlData(List.of(
                    new TenantSsoEntry("tenant-r", "r.example.com", true,
                            List.of(), "PT3H", "PT10M")
            ));
        });

        adapter.init();   // falla → cache vacío → system defaults
        assertThat(adapter.resolveTtl("tenant-r").absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);

        shouldFail.set(false);
        adapter.refresh();  // ahora tiene éxito

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-r");
        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(3));
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(10));
    }
}
