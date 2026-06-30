package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT: ES-01 — aislamiento de entradas de catálogo malformadas.
 *
 * Garantías verificadas:
 *   1. Una entrada con clientId null/blank se descarta individualmente, no aborta el tenant.
 *   2. El descarte no afecta a los demás clientes del mismo tenant ni a otros tenants.
 *   3. Se emite un log estructurado con event=sso_catalog_entry_discarded por cada entrada inválida.
 *   4. Lista nula → catálogo vacío sin emitir sso_catalog_entry_discarded.
 *
 * Implementación: instanciación directa del adapter (POJO + AtomicReference).
 * No se necesita Spring ni Testcontainers.
 */
class TenantSsoCatalogMalformedIT {

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
    // ES-01: entrada con clientId null descartada individualmente
    // Los clientes válidos del mismo tenant se conservan intactos.
    // =========================================================

    @Test
    void init_discardsMalformedEntry_whenClientIdIsNull() {
        List<String> entriesWithNull = new ArrayList<>();
        entriesWithNull.add(null);
        entriesWithNull.add("valid-client");

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-a", "a.example.com", true,
                                entriesWithNull, null, null)
                ))
        );
        adapter.init();

        TenantSsoCatalog catalog = adapter.resolveEligibleClients("tenant-a");

        assertThat(catalog.contains("valid-client")).isTrue();
        assertThat(logCaptor.list)
                .anyMatch(e -> e.getFormattedMessage().contains("event=sso_catalog_entry_discarded")
                               && e.getFormattedMessage().contains("tenant=tenant-a"));
    }

    // =========================================================
    // ES-01: entrada con clientId blank descartada individualmente
    // El cliente válido del mismo tenant se conserva.
    // =========================================================

    @Test
    void init_discardsMalformedEntry_whenClientIdIsBlank() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-b", "b.example.com", true,
                                List.of("   ", "client-b"), null, null)
                ))
        );
        adapter.init();

        TenantSsoCatalog catalog = adapter.resolveEligibleClients("tenant-b");

        assertThat(catalog.contains("client-b")).isTrue();
        assertThat(logCaptor.list)
                .anyMatch(e -> e.getFormattedMessage().contains("event=sso_catalog_entry_discarded")
                               && e.getFormattedMessage().contains("tenant=tenant-b"));
    }

    // =========================================================
    // ES-01: entradas malformadas en un tenant no abortan otros tenants
    //
    // tenant-bad tiene sólo entradas inválidas → catálogo vacío.
    // tenant-good carga correctamente con todos sus clientes.
    // =========================================================

    @Test
    void init_doesNotAbortOtherTenants_whenOneHasMalformedEntries() {
        List<String> malformed = new ArrayList<>();
        malformed.add(null);
        malformed.add("   ");

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-bad",  "bad.example.com",  true, malformed,
                                null, null),
                        new TenantSsoEntry("tenant-good", "good.example.com", true,
                                List.of("good-client-1", "good-client-2"), null, null)
                ))
        );
        adapter.init();

        TenantSsoCatalog badCatalog  = adapter.resolveEligibleClients("tenant-bad");
        TenantSsoCatalog goodCatalog = adapter.resolveEligibleClients("tenant-good");

        // Catálogo del tenant malformado: sin clientes válidos (fail-closed)
        assertThat(badCatalog.contains("good-client-1")).isFalse();

        // Catálogo del tenant correcto: clientes intactos
        assertThat(goodCatalog.contains("good-client-1")).isTrue();
        assertThat(goodCatalog.contains("good-client-2")).isTrue();
    }

    // =========================================================
    // ES-01: se emite exactamente un log por cada entrada inválida
    // =========================================================

    @Test
    void init_emitsOneLogPerDiscardedEntry() {
        List<String> mixed = new ArrayList<>();
        mixed.add(null);
        mixed.add("   ");
        mixed.add("valid-survivor");

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-multi", "multi.example.com", true,
                                mixed, null, null)
                ))
        );
        adapter.init();

        long discardedLogs = logCaptor.list.stream()
                .filter(e -> e.getFormattedMessage().contains("event=sso_catalog_entry_discarded"))
                .count();

        // Un log por cada entrada inválida (null + blank = 2), la válida no genera log
        assertThat(discardedLogs).isEqualTo(2);

        // El cliente válido sigue presente en el catálogo
        assertThat(adapter.resolveEligibleClients("tenant-multi").contains("valid-survivor")).isTrue();
    }

    // =========================================================
    // ES-01: lista nula en eligibleClients → catálogo vacío, sin log de descarte
    //
    // Una lista nula se trata como "sin entradas definidas" (no es una entrada
    // malformada): catálogo vacío pero sin emitir sso_catalog_entry_discarded.
    // =========================================================

    @Test
    void init_returnsCatalogEmpty_whenEligibleClientsListIsNull() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-null-list", "null.example.com", true,
                                null, null, null)
                ))
        );
        adapter.init();

        TenantSsoCatalog catalog = adapter.resolveEligibleClients("tenant-null-list");
        assertThat(catalog.contains("any-client")).isFalse();

        assertThat(logCaptor.list)
                .noneMatch(e -> e.getFormattedMessage().contains("event=sso_catalog_entry_discarded"));
    }

    // =========================================================
    // ES-01: lista vacía en eligibleClients → catálogo vacío, sin log de descarte
    // =========================================================

    @Test
    void init_returnsCatalogEmpty_whenEligibleClientsListIsEmpty() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-empty-list", "empty.example.com", true,
                                List.of(), null, null)
                ))
        );
        adapter.init();

        TenantSsoCatalog catalog = adapter.resolveEligibleClients("tenant-empty-list");
        assertThat(catalog.contains("any-client")).isFalse();

        assertThat(logCaptor.list)
                .noneMatch(e -> e.getFormattedMessage().contains("event=sso_catalog_entry_discarded"));
    }
}
