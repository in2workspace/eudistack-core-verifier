package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * IT — ES-02: resiliencia del catálogo SSO ante fallos de lectura de configuración.
 *
 * Verifica que:
 * - Fail-closed: sin config previa {@code resolveEligibleClients()} devuelve catálogo vacío.
 * - El patrón {@code AtomicReference} conserva el último catálogo válido cuando {@code refresh()}
 *   lanza excepción (el cache NO se actualiza en caso de fallo).
 * - El log de error {@code event=sso_config_refresh_failed} se emite en cada fallo.
 * - Múltiples fallos consecutivos no corrompen el catálogo.
 * - Tras una recuperación exitosa el catálogo refleja los nuevos datos.
 * - {@code eligibleClients=null} en YAML resulta en catálogo vacío (compact constructor +
 *   parseEligibleClients).
 */
@ExtendWith(MockitoExtension.class)
class TenantSsoConfigCatalogReadFailureIT {

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

    // =========================================================
    // ES-02 FAIL-CLOSED: sin config previa → catálogo vacío
    // resolveEligibleClients devuelve TenantSsoCatalog.empty() cuando
    // el tenant no tiene config registrada (orElseGet(TenantSsoCatalog::empty)).
    // =========================================================
    @Test
    void resolveEligibleClients_shouldReturnEmptyCatalog_whenTenantHasNoConfig() {
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of()));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        TenantSsoCatalog catalog = configPort.resolveEligibleClients("unknown-tenant");

        assertThat(catalog.isEmpty())
                .as("Sin config previa el catálogo debe ser vacío (fail-closed)")
                .isTrue();
        assertThat(catalog.contains("any-client"))
                .as("Un catálogo vacío no contiene ningún cliente")
                .isFalse();
    }

    // =========================================================
    // ES-02 ATÓMICA: refresh() falla → último catálogo válido conservado
    // El AtomicReference NO se actualiza si load() lanza; el catálogo
    // del init() permanece disponible.
    // =========================================================
    @Test
    void resolveEligibleClients_shouldRetainLastValidCatalog_whenRefreshFails() {
        TenantSsoConfigYamlData validData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("client-x", "client-y"), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(validData);

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        // Verificamos que el catálogo inicial es correcto
        TenantSsoCatalog beforeRefresh = configPort.resolveEligibleClients("tenant-a");
        assertThat(beforeRefresh.contains("client-x")).isTrue();
        assertThat(beforeRefresh.contains("client-y")).isTrue();

        // El provider falla en el siguiente refresh
        when(provider.retrieve()).thenThrow(new RuntimeException("datasource unavailable"));
        adapter.refresh();

        // El catálogo debe seguir siendo el del init() — cache no modificado
        TenantSsoCatalog afterRefresh = configPort.resolveEligibleClients("tenant-a");
        assertThat(afterRefresh.contains("client-x"))
                .as("client-x debe seguir en el catálogo tras refresh fallido")
                .isTrue();
        assertThat(afterRefresh.contains("client-y"))
                .as("client-y debe seguir en el catálogo tras refresh fallido")
                .isTrue();
        assertThat(afterRefresh.size()).isEqualTo(2);
    }

    // =========================================================
    // ES-02 LOG: refresh() fallido emite event=sso_config_refresh_failed
    // El error es observable en los logs de auditoría/operaciones.
    // =========================================================
    @Test
    void refresh_shouldEmitErrorLog_whenProviderFails() {
        when(provider.retrieve())
                .thenReturn(new TenantSsoConfigYamlData(List.of()))
                .thenThrow(new RuntimeException("I/O error reading config file"));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        adapter.refresh();

        boolean errorLogged = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null && msg.contains("sso_config_refresh_failed");
                });

        assertThat(errorLogged)
                .as("Debe emitirse ERROR con event=sso_config_refresh_failed")
                .isTrue();
    }

    // =========================================================
    // ES-02 MULTIPLES FALLOS: N fallos consecutivos → catálogo siempre presente
    // Verifica que la preservación del cache es durable, no solo en el primer fallo.
    // =========================================================
    @Test
    void resolveEligibleClients_shouldPreserveCatalog_afterMultipleConsecutiveRefreshFailures() {
        TenantSsoConfigYamlData validData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-b", "b.example.com", true,
                        List.of("client-1", "client-2", "client-3"), "PT2H", "PT10M")
        ));
        when(provider.retrieve())
                .thenReturn(validData)
                .thenThrow(new RuntimeException("fail-1"))
                .thenThrow(new RuntimeException("fail-2"))
                .thenThrow(new RuntimeException("fail-3"));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        adapter.refresh(); // fail-1
        adapter.refresh(); // fail-2
        adapter.refresh(); // fail-3

        TenantSsoCatalog catalog = configPort.resolveEligibleClients("tenant-b");

        assertThat(catalog.isEmpty())
                .as("Tras 3 fallos el catálogo no debe quedar vacío")
                .isFalse();
        assertThat(catalog.size()).isEqualTo(3);
        assertThat(catalog.contains("client-1")).isTrue();
        assertThat(catalog.contains("client-2")).isTrue();
        assertThat(catalog.contains("client-3")).isTrue();
    }

    // =========================================================
    // ES-02 RECUPERACIÓN: refresh() exitoso tras fallo → nuevo catálogo aplicado
    // La preservación no bloquea actualizaciones cuando el provider se recupera.
    // =========================================================
    @Test
    void resolveEligibleClients_shouldApplyNewCatalog_whenRefreshSucceedsAfterFailure() {
        TenantSsoConfigYamlData initialData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("old-client"), "PT2H", "PT10M")
        ));
        TenantSsoConfigYamlData recoveredData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("new-client-1", "new-client-2"), "PT2H", "PT10M")
        ));

        when(provider.retrieve())
                .thenReturn(initialData)
                .thenThrow(new RuntimeException("transient-error"))
                .thenReturn(recoveredData);

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        // Fallo intermedio: catálogo original conservado
        adapter.refresh();
        assertThat(configPort.resolveEligibleClients("tenant-a").contains("old-client"))
                .as("Tras fallo transitorio, old-client debe seguir en el catálogo")
                .isTrue();

        // Recuperación: nuevo catálogo aplicado
        adapter.refresh();
        TenantSsoCatalog newCatalog = configPort.resolveEligibleClients("tenant-a");
        assertThat(newCatalog.contains("new-client-1"))
                .as("Tras recuperación exitosa, new-client-1 debe estar en el catálogo")
                .isTrue();
        assertThat(newCatalog.contains("new-client-2"))
                .as("Tras recuperación exitosa, new-client-2 debe estar en el catálogo")
                .isTrue();
        assertThat(newCatalog.contains("old-client"))
                .as("old-client no debe estar en el catálogo tras actualización")
                .isFalse();
    }

    // =========================================================
    // ES-02 NULL EN YAML: eligibleClients=null en YAML → catálogo vacío (fail-closed)
    // TenantSsoEntry compact constructor normaliza null → List.of();
    // el catálogo resultante es vacío pero el tenant sí tiene config (no REJECT_CATALOG
    // por ausencia de config, sino catálogo vacío).
    // =========================================================
    @Test
    void resolveEligibleClients_shouldReturnEmptyCatalog_whenEligibleClientsIsNullInYaml() {
        // null como eligibleClients → TenantSsoEntry compact constructor lo convierte a List.of()
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        null, "PT2H", "PT10M")
        )));

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        // El tenant tiene config (fail-closed, no ausencia de config)
        assertThat(configPort.getByTenant("tenant-a")).isPresent();

        // Pero su catálogo es vacío porque eligibleClients era null en YAML
        TenantSsoCatalog catalog = configPort.resolveEligibleClients("tenant-a");
        assertThat(catalog.isEmpty())
                .as("eligibleClients=null en YAML debe resultar en catálogo vacío (fail-closed)")
                .isTrue();
        assertThat(catalog.contains("any-client"))
                .as("El catálogo vacío no debe autorizar ningún cliente")
                .isFalse();
    }

    // =========================================================
    // ES-02 AISLAMIENTO: refresh() falla pero otros tenants no se ven afectados
    // El cache falla atómicamente: todos los tenants son de la última carga exitosa.
    // =========================================================
    @Test
    void resolveEligibleClients_shouldPreserveAllTenants_whenRefreshFails() {
        TenantSsoConfigYamlData validData = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("client-a"), "PT2H", "PT10M"),
                new TenantSsoEntry("tenant-b", "b.example.com", true,
                        List.of("client-b"), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(validData);

        adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        when(provider.retrieve()).thenThrow(new RuntimeException("network timeout"));
        adapter.refresh();

        // Ambos tenants deben seguir accesibles tras el fallo
        assertThat(configPort.resolveEligibleClients("tenant-a").contains("client-a"))
                .as("tenant-a debe conservar su catálogo tras refresh fallido")
                .isTrue();
        assertThat(configPort.resolveEligibleClients("tenant-b").contains("client-b"))
                .as("tenant-b debe conservar su catálogo tras refresh fallido")
                .isTrue();
    }
}
