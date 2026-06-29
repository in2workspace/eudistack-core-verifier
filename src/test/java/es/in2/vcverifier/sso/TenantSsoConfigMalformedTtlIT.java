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

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT: ES-01 — aislamiento por tenant ante valor TTL malformado.
 *
 * Garantías verificadas:
 *   1. Un tenant con TTL malformado no aborta la carga de otros tenants.
 *   2. El tenant afectado recibe los valores default (no defaults de otro tenant).
 *   3. Se emite un log estructurado con event=sso_ttl_parse_error.
 *
 * Implementación: instanciación directa del adapter (POJO + AtomicReference).
 * No se necesita Spring ni Testcontainers.
 */
class TenantSsoConfigMalformedTtlIT {

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
    // ES-01: valor malformado en un tenant no aborta los demás
    // =========================================================

    @Test
    void init_loadsAllTenants_whenOneTenantHasMalformedTtl() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-bad",  "a.example.com", true, List.of(), "NOT_A_DURATION", "ALSO_BAD"),
                        new TenantSsoEntry("tenant-good", "b.example.com", true, List.of(), "PT4H",           "PT15M")
                ))
        );
        adapter.init();

        // El tenant malformado recibe los defaults del sistema
        SsoSessionTtl badTtl = adapter.resolveTtl("tenant-bad");
        assertThat(badTtl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(badTtl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);

        // El tenant correcto recibe su override
        SsoSessionTtl goodTtl = adapter.resolveTtl("tenant-good");
        assertThat(goodTtl.absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(goodTtl.idle()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void init_emitsStructuredLog_whenTtlIsMalformed() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-x", "x.example.com", true, List.of(), "GARBAGE_VALUE", null)
                ))
        );
        adapter.init();

        assertThat(logCaptor.list)
                .anyMatch(e -> e.getFormattedMessage().contains("event=sso_ttl_parse_error"))
                .anyMatch(e -> e.getFormattedMessage().contains("tenant=tenant-x"))
                .anyMatch(e -> e.getFormattedMessage().contains("field=ttlAbsolute"))
                .anyMatch(e -> e.getFormattedMessage().contains("value=GARBAGE_VALUE"));
    }

    @Test
    void init_emitsLogPerMalformedField_whenBothTtlsAreMalformed() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-y", "y.example.com", true, List.of(), "BAD_ABS", "BAD_IDLE")
                ))
        );
        adapter.init();

        long errorCount = logCaptor.list.stream()
                .filter(e -> e.getFormattedMessage().contains("event=sso_ttl_parse_error"))
                .count();

        // Un log por cada campo malformado (ttlAbsolute + ttlIdle)
        assertThat(errorCount).isEqualTo(2);
    }

    @Test
    void init_doesNotLogParseError_whenTtlIsAbsent() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-z", "z.example.com", true, List.of(), null, null)
                ))
        );
        adapter.init();

        assertThat(logCaptor.list)
                .noneMatch(e -> e.getFormattedMessage().contains("event=sso_ttl_parse_error"));
    }

    @Test
    void init_doesNotLogParseError_whenTtlIsBlank() {
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-blank", "b.example.com", true, List.of(), "  ", "")
                ))
        );
        adapter.init();

        assertThat(logCaptor.list)
                .noneMatch(e -> e.getFormattedMessage().contains("event=sso_ttl_parse_error"));
    }

    @Test
    void init_treatsOutOfRangeTtlAsDefault_whenAbsoluteTtlExceedsMaximum() {
        // PT100H (100h) supera MAX_ABSOLUTE (24h) → TenantSsoTtlPolicy.resolve() aplica el default
        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(() ->
                new TenantSsoConfigYamlData(List.of(
                        new TenantSsoEntry("tenant-oob", "oob.example.com", true, List.of(), "PT100H", "PT15M")
                ))
        );
        adapter.init();

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-oob");

        // Sólo la dimensión inválida cae al default; la otra conserva su override
        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(15));
    }
}
