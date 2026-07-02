package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * IT — Resolución de TTL de sesiones SSO a través de TenantSsoConfigYamlAdapter.
 *
 * AC-01  Tenant sin TTL configurado → valores por defecto del sistema (ADR-106).
 * AC-02  Tenant con ttlAbsolute y ttlIdle válidos → valores configurados exactos.
 * EC-03  Override parcial (solo ttlAbsolute) → absolute configurado + idle default.
 *
 * No necesita Spring context: prueba la integración entre el adaptador YAML,
 * TenantSsoTtlPolicy y TenantSsoConfigPort.resolveTtl().
 */
@ExtendWith(MockitoExtension.class)
class TenantSsoTtlResolutionIT {

    @Mock
    private TenantSsoConfigProvider provider;

    private TenantSsoConfigPort configPort;

    @BeforeEach
    void setUp() {
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlData(List.of(
                // AC-01: sin TTL → defaults
                new TenantSsoEntry("default-tenant", "default.example.com", true,
                        List.of("client-a"), null, null),
                // AC-02: TTL completo válido
                new TenantSsoEntry("custom-tenant", "custom.example.com", true,
                        List.of("client-a"), "PT4H", "PT15M"),
                // EC-03: solo ttlAbsolute
                new TenantSsoEntry("partial-tenant", "partial.example.com", true,
                        List.of(), "PT4H", null)
        ));

        when(provider.retrieve()).thenReturn(data);

        TenantSsoConfigYamlAdapter adapter = new TenantSsoConfigYamlAdapter(provider);
        adapter.init();
        configPort = adapter;
    }

    // AC-01: tenant sin TTL configurado → DEFAULT_ABSOLUTE / DEFAULT_IDLE (ADR-106)
    @Test
    void resolveTtl_shouldReturnSystemDefaults_whenNoTtlConfigured() {
        SsoSessionTtl ttl = configPort.resolveTtl("default-tenant");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // AC-02: tenant con ttlAbsolute="PT4H" y ttlIdle="PT15M" → valores exactos
    @Test
    void resolveTtl_shouldReturnConfiguredValues_whenValidTtlProvided() {
        SsoSessionTtl ttl = configPort.resolveTtl("custom-tenant");

        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(15));
    }

    // EC-03: solo ttlAbsolute configurado; ttlIdle ausente → absolute del override, idle default
    @Test
    void resolveTtl_shouldUseDefaultIdle_whenOnlyAbsoluteIsConfigured() {
        SsoSessionTtl ttl = configPort.resolveTtl("partial-tenant");

        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // Tenant desconocido → systemDefault() sin excepción (orElseGet en resolveTtl)
    @Test
    void resolveTtl_shouldReturnSystemDefault_whenTenantNotFound() {
        SsoSessionTtl ttl = configPort.resolveTtl("unknown-tenant");

        assertThat(ttl).isEqualTo(SsoSessionTtl.systemDefault());
    }
}
