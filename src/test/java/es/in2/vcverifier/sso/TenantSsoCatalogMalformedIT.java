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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * IT — ES-01: parseo defensivo de entradas mal formadas en {@code eligibleClients}.
 *
 * Verifica que:
 * - Una entrada nula o en blanco emite WARN con {@code event=sso_catalog_entry_malformed}
 *   y la entrada se descarta del catálogo resultante.
 * - El aislamiento per-tenant funciona: el fallo de parseo en un tenant NO aborta
 *   la carga de los demás.
 * - Las entradas válidas presentes junto a malformadas se incorporan correctamente.
 * - Si todas las entradas son malformadas el catálogo es vacío (fail-closed AC-03).
 */
@ExtendWith(MockitoExtension.class)
class TenantSsoCatalogMalformedIT {

    @Mock
    private TenantSsoConfigProvider provider;

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
    // ES-01: entrada nula en la lista → WARN + descarte
    // =========================================================
    @Test
    void init_shouldEmitWarnLog_whenNullEntryInEligibleClients() {
        // List.of no admite null; se usa Arrays.asList (dos args → no hay ambigüedad varargs).
        // Se construye ANTES de when() para no dejar Mockito en stubbing incompleto si algo falla.
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        Arrays.asList(null, "client-valid"), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        boolean warnFound = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null
                            && msg.contains("sso_catalog_entry_malformed")
                            && msg.contains("tenant-a")
                            && msg.contains("null_or_blank");
                });

        assertThat(warnFound)
                .as("Debe emitirse WARN event=sso_catalog_entry_malformed para entrada null")
                .isTrue();
    }

    // =========================================================
    // ES-01: entrada en blanco (string vacío) → WARN + descarte
    // =========================================================
    @Test
    void init_shouldEmitWarnLog_whenEmptyStringEntryInEligibleClients() {
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("", "client-valid"), "PT2H", "PT10M")
        )));

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        boolean warnFound = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null
                            && msg.contains("sso_catalog_entry_malformed")
                            && msg.contains("tenant-a")
                            && msg.contains("null_or_blank");
                });

        assertThat(warnFound)
                .as("Debe emitirse WARN event=sso_catalog_entry_malformed para entrada vacía")
                .isTrue();
    }

    // =========================================================
    // ES-01: entrada solo de espacios → WARN + descarte
    // =========================================================
    @Test
    void init_shouldEmitWarnLog_whenWhitespaceOnlyEntryInEligibleClients() {
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("   ", "client-valid"), "PT2H", "PT10M")
        )));

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        boolean warnFound = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null
                            && msg.contains("sso_catalog_entry_malformed")
                            && msg.contains("null_or_blank");
                });

        assertThat(warnFound)
                .as("Debe emitirse WARN event=sso_catalog_entry_malformed para entrada de solo espacios")
                .isTrue();
    }

    // =========================================================
    // ES-01: entradas mixtas → solo las válidas forman el catálogo
    // Null, vacío y espacios se descartan; la entrada válida permanece.
    // =========================================================
    @Test
    void init_shouldKeepOnlyValidEntries_whenListContainsMixedContent() {
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        Arrays.asList(null, "", "  ", "client-valid-1", "client-valid-2"),
                        "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        TenantSsoCatalog catalog = configPort.resolveEligibleClients("tenant-a");

        assertThat(catalog.isEmpty()).isFalse();
        assertThat(catalog.size()).isEqualTo(2);
        assertThat(catalog.contains("client-valid-1")).isTrue();
        assertThat(catalog.contains("client-valid-2")).isTrue();
        // Las entradas malformadas no deben estar presentes
        assertThat(catalog.contains("")).isFalse();
        assertThat(catalog.contains("   ")).isFalse();
    }

    // =========================================================
    // ES-01: todas las entradas malformadas → catálogo vacío (fail-closed AC-03)
    // El tenant sigue siendo cargado en la config; su catálogo es vacío.
    // =========================================================
    @Test
    void init_shouldReturnEmptyCatalog_whenAllEntriesAreMalformed() {
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        Arrays.asList(null, "", "   "), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        TenantSsoCatalog catalog = configPort.resolveEligibleClients("tenant-a");

        assertThat(catalog.isEmpty())
                .as("Catálogo vacío (fail-closed) cuando todas las entradas son malformadas")
                .isTrue();
        // El tenant sí existe en config (solo su catálogo es vacío)
        assertThat(configPort.getByTenant("tenant-a")).isPresent();
    }

    // =========================================================
    // ES-01 AISLAMIENTO: entradas malformadas en tenant-a no afectan a tenant-b
    // El error de parseo de un tenant no aborta la carga de los demás (per-tenant isolation).
    // =========================================================
    @Test
    void init_shouldNotAbortOtherTenants_whenOneHasMalformedEligibleClients() {
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                // tenant-a: lista con entradas malformadas (null y vacío)
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        Arrays.asList(null, ""), "PT2H", "PT10M"),
                // tenant-b: lista completamente válida
                new TenantSsoEntry("tenant-b", "b.example.com", true,
                        List.of("rp-client-1", "rp-client-2"), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        // tenant-a: catálogo vacío (entradas descartadas)
        TenantSsoCatalog catalogA = configPort.resolveEligibleClients("tenant-a");
        assertThat(catalogA.isEmpty())
                .as("tenant-a: catálogo vacío porque todas sus entradas eran malformadas")
                .isTrue();

        // tenant-b: catálogo completo, no afectado por los errores de tenant-a
        TenantSsoCatalog catalogB = configPort.resolveEligibleClients("tenant-b");
        assertThat(catalogB.isEmpty())
                .as("tenant-b: no debe verse afectado por las entradas malformadas de tenant-a")
                .isFalse();
        assertThat(catalogB.size()).isEqualTo(2);
        assertThat(catalogB.contains("rp-client-1")).isTrue();
        assertThat(catalogB.contains("rp-client-2")).isTrue();
    }

    // =========================================================
    // ES-01 AISLAMIENTO: log WARN referencia únicamente al tenant malformado
    // No debe existir log de error sobre tenant-b cuando solo tenant-a falla.
    // =========================================================
    @Test
    void init_shouldOnlyLogWarnForMalformedTenant_notForHealthyTenant() {
        // Arrays.asList(null) con un solo argumento null lanza NPE (varargs ambigüedad);
        // se construye la lista explícitamente y ANTES de llamar a when() para no dejar
        // Mockito en estado de stubbing incompleto si ocurre algún error.
        List<String> tenantAClients = new ArrayList<>();
        tenantAClients.add(null);

        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        tenantAClients, "PT2H", "PT10M"),
                new TenantSsoEntry("tenant-b", "b.example.com", true,
                        List.of("client-ok"), "PT2H", "PT10M")
        ));
        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();

        long warnCountForB = logAppender.list.stream()
                .filter(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null
                            && msg.contains("sso_catalog_entry_malformed")
                            && msg.contains("tenant-b");
                })
                .count();

        assertThat(warnCountForB)
                .as("No debe emitirse ningún WARN de catálogo mal formado sobre tenant-b")
                .isZero();
    }

    // =========================================================
    // ES-01: entrada válida con espacios laterales → normalizada (no descartada)
    // SsoEligibleClient.of() aplica trim; la entrada "  client-a  " resulta en "client-a".
    // =========================================================
    @Test
    void init_shouldNormalizeWhitespaceInValidEntry_notDiscardIt() {
        when(provider.retrieve()).thenReturn(new TenantSsoConfigYamlData(List.of(
                new TenantSsoEntry("tenant-a", "a.example.com", true,
                        List.of("  client-a  "), "PT2H", "PT10M")
        )));

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;

        TenantSsoCatalog catalog = configPort.resolveEligibleClients("tenant-a");

        // La entrada con espacios laterales es válida (no blank); se normaliza a "client-a"
        assertThat(catalog.contains("client-a"))
                .as("Entrada con espacios laterales debe normalizarse a 'client-a', no descartarse")
                .isTrue();
        assertThat(catalog.size()).isEqualTo(1);
    }
}
