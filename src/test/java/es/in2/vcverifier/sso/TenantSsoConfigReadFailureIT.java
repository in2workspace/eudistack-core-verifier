package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * IT — ES-02: fail-safe a última configuración válida ante fallo de lectura.
 *
 * Verifica que:
 * - Si {@code refresh()} lanza excepción, el cache NO se actualiza y la última
 *   config válida se conserva (patrón AtomicReference).
 * - Se emite el log de error con event=sso_config_refresh_failed.
 * - Si el tenant no tiene config registrada, {@code resolveTtl()} devuelve
 *   {@link SsoSessionTtl#systemDefault()} (fallback a default del sistema).
 */
@ExtendWith(MockitoExtension.class)
class TenantSsoConfigReadFailureIT {

    @Mock
    private TenantSsoConfigProvider provider;

    private TenantSsoConfigYamlAdapter adapter;
    private TenantSsoConfigPort configPort;

    private ListAppender<ILoggingEvent> logAppender;
    private Logger adapterLogger;

    @BeforeEach
    void setUpLogger() {
        adapterLogger = (Logger) LoggerFactory.getLogger(TenantSsoConfigYamlAdapter.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        adapterLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        adapterLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    // ES-02: refresh() lanza → cache retiene última config válida cargada en init()
    @Test
    void refresh_shouldRetainLastValidConfig_whenProviderThrows() {
        // GIVEN: carga inicial exitosa con tenant-a configurado
        TenantSsoConfigYamlData validData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of(), "PT4H", "PT15M")
        ));
        when(provider.retrieve()).thenReturn(validData);

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        // WHEN: el provider falla en el siguiente intento de refresh
        when(provider.retrieve()).thenThrow(new RuntimeException("Config file unavailable"));
        adapter.refresh();

        // THEN: la config del init() se conserva intacta
        Optional<TenantSsoConfig> config = adapter.getByTenant("tenant-a");

        assertThat(config).isPresent();
        assertThat(config.get().ttl().absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(config.get().ttl().idle()).isEqualTo(Duration.ofMinutes(15));
    }

    // ES-02: el fallo de refresh emite log de error con event=sso_config_refresh_failed
    @Test
    void refresh_shouldEmitErrorLog_whenProviderThrows() {
        when(provider.retrieve())
                .thenReturn(new TenantSsoConfigYamlData(List.of()))
                .thenThrow(new RuntimeException("Config file unavailable"));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        adapter.refresh();

        boolean errorFound = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null && msg.contains("sso_config_refresh_failed");
                });

        assertThat(errorFound)
                .as("Debe emitirse un ERROR con event=sso_config_refresh_failed")
                .isTrue();
    }

    // ES-02 fallback a default: tenant desconocido → resolveTtl() devuelve systemDefault()
    @Test
    void resolveTtl_shouldReturnSystemDefault_whenTenantHasNoConfig() {
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of()));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        // resolveTtl usa orElseGet(SsoSessionTtl::systemDefault) cuando getByTenant vacío
        SsoSessionTtl ttl = configPort.resolveTtl("any-tenant");

        assertThat(ttl).isEqualTo(SsoSessionTtl.systemDefault());
    }

    // ES-02: multiples fallos de refresh consecutivos → config siempre conservada
    @Test
    void refresh_shouldPreserveConfig_afterMultipleConsecutiveFailures() {
        TenantSsoConfigYamlData validData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-b", "b.example.com", true,
                        List.of(), "PT2H", "PT10M")
        ));
        when(provider.retrieve())
                .thenReturn(validData)
                .thenThrow(new RuntimeException("fail-1"))
                .thenThrow(new RuntimeException("fail-2"))
                .thenThrow(new RuntimeException("fail-3"));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        adapter.refresh(); // fail-1
        adapter.refresh(); // fail-2
        adapter.refresh(); // fail-3

        Optional<TenantSsoConfig> config = adapter.getByTenant("tenant-b");

        assertThat(config).isPresent();
        assertThat(config.get().ttl().absolute()).isEqualTo(Duration.ofHours(2));
    }
}
