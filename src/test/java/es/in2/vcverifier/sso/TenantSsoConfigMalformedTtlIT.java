package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * IT — ES-01: valor de TTL mal formado en YAML tratado como ausente.
 *
 * Verifica que:
 * - Un valor ttlAbsolute no parseable (e.g. "NOT_A_DURATION") emite un WARN estructurado
 *   con event=sso_ttl_malformed y aplica el default del sistema para ese tenant.
 * - El error de un tenant NO aborta la carga de los demás tenants (aislamiento per-tenant).
 * - El tenant con TTL válido carga sus valores configurados correctamente.
 */
@ExtendWith(MockitoExtension.class)
class TenantSsoConfigMalformedTtlIT {

    @Mock
    private TenantSsoConfigProvider provider;

    private TenantSsoConfigPort configPort;

    private ListAppender<ILoggingEvent> logAppender;
    private Logger adapterLogger;

    @BeforeEach
    void setUp() {
        adapterLogger = (Logger) LoggerFactory.getLogger(TenantSsoConfigYamlAdapter.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        adapterLogger.addAppender(logAppender);

        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                // ttlAbsolute mal formado, ttlIdle válido → ambos tratados independientemente
                new TenantSsoEntry("bad-tenant", "bad.example.com", true,
                        List.of(), "NOT_A_DURATION", "PT20M"),
                // Tenant con TTL completamente válido
                new TenantSsoEntry("good-tenant", "good.example.com", true,
                        List.of(), "PT6H", "PT20M")
        ));

        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;
    }

    @AfterEach
    void tearDown() {
        adapterLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    // ES-01: valor mal formado → log WARN con event=sso_ttl_malformed
    @Test
    void init_shouldEmitWarnLog_whenTtlAbsoluteIsMalformed() {
        boolean warnFound = logAppender.list.stream()
                .anyMatch(e -> {
                    String msg = e.getFormattedMessage();
                    return msg != null
                            && msg.contains("sso_ttl_malformed")
                            && msg.contains("bad-tenant")
                            && msg.contains("ttlAbsolute");
                });

        assertThat(warnFound)
                .as("Debe emitirse un WARN con event=sso_ttl_malformed para bad-tenant/ttlAbsolute")
                .isTrue();
    }

    // ES-01: tenant con TTL mal formado → recibe valores por defecto del sistema (no aborta)
    @Test
    void init_shouldApplySystemDefaults_whenTtlAbsoluteIsMalformed() {
        var config = configPort.getByTenant("bad-tenant");

        assertThat(config).isPresent();
        // Absolute mal formado → DEFAULT_ABSOLUTE; idle "PT20M" sí se parsea pero, como el
        // absolute cayó al default (PT8H), idle PT20M ≤ PT8H → se respeta.
        assertThat(config.get().ttl().absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(config.get().ttl().idle()).isEqualTo(Duration.ofMinutes(20));
    }

    // ES-01 aislamiento: el error de bad-tenant NO impide que good-tenant cargue correctamente
    @Test
    void init_shouldLoadGoodTenantSuccessfully_despiteMalformedTtlInOtherTenant() {
        var config = configPort.getByTenant("good-tenant");

        assertThat(config).isPresent();
        assertThat(config.get().ttl().absolute()).isEqualTo(Duration.ofHours(6));
        assertThat(config.get().ttl().idle()).isEqualTo(Duration.ofMinutes(20));
    }
}
