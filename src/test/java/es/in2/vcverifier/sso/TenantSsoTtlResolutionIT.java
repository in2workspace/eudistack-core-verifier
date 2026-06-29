package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IT: TenantSsoConfigYamlAdapter.resolveTtl() — resolución efectiva de TTL por tenant.
 *
 * Escenarios:
 *   AC-01: sin override en YAML → devuelve defaults del sistema
 *   AC-02: override válido en ambas dimensiones → devuelve los overrides
 *   EC-03: override parcial (sólo absolute especificado) → absolute override + idle default
 *
 * No necesita contexto Spring ni Testcontainers: el adapter es un POJO con
 * TenantSsoTtlPolicy y AtomicReference internos instanciables directamente.
 */
class TenantSsoTtlResolutionIT {

    // =========================================================
    // HELPERS
    // =========================================================

    private TenantSsoConfigYamlAdapter adapterWith(List<TenantSsoEntry> entries) {
        TenantSsoConfigYamlAdapter adapter =
                new TenantSsoConfigYamlAdapter(() -> new TenantSsoConfigYamlData(entries));
        adapter.init();
        return adapter;
    }

    private TenantSsoEntry entry(String tenant, String ttlAbsolute, String ttlIdle) {
        return new TenantSsoEntry(tenant, "domain.example.com", true,
                List.of("client-a"), ttlAbsolute, ttlIdle);
    }

    // =========================================================
    // AC-01: sin override → defaults del sistema
    // =========================================================

    @Test
    void resolveTtl_returnsSystemDefaults_whenNoTtlOverrideInYaml() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-a", null, null)
        ));

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-a");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    @Test
    void resolveTtl_returnsSystemDefaults_forUnknownTenant() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of());

        SsoSessionTtl ttl = adapter.resolveTtl("unknown-tenant");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    @Test
    void resolveTtl_returnsSystemDefaults_whenTenantIsNull() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of());

        SsoSessionTtl ttl = adapter.resolveTtl(null);

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // =========================================================
    // AC-02: override válido en ambas dimensiones → se usa el override
    // =========================================================

    @Test
    void resolveTtl_returnsOverrideValues_whenBothTtlsAreValidIso8601() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-b", "PT4H", "PT15M")
        ));

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-b");

        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void resolveTtl_returnsMaxBoundary_whenTtlsAreAtMaximum() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-c", "PT24H", "PT8H")
        ));

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-c");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.MAX_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.MAX_IDLE);
    }

    @Test
    void resolveTtl_tenantLookupIsCaseInsensitive() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-d", "PT6H", "PT20M")
        ));

        // tenant name normalised to lower-case on load
        SsoSessionTtl ttl = adapter.resolveTtl("TENANT-D");

        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(6));
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(20));
    }

    // =========================================================
    // EC-03: override parcial → la dimensión ausente usa el default
    // =========================================================

    @Test
    void resolveTtl_usesOverrideAbsoluteAndDefaultIdle_whenOnlyAbsoluteSpecified() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-e", "PT4H", null)
        ));

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-e");

        assertThat(ttl.absolute()).isEqualTo(Duration.ofHours(4));
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    @Test
    void resolveTtl_usesDefaultAbsoluteAndOverrideIdle_whenOnlyIdleSpecified() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-f", null, "PT10M")
        ));

        SsoSessionTtl ttl = adapter.resolveTtl("tenant-f");

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(Duration.ofMinutes(10));
    }

    // =========================================================
    // Multitenancy: cada tenant resuelve su propio TTL
    // =========================================================

    @Test
    void resolveTtl_resolvesTtlIndependentlyPerTenant() {
        TenantSsoConfigYamlAdapter adapter = adapterWith(List.of(
                entry("tenant-x", "PT2H", "PT5M"),
                entry("tenant-y", null, null)
        ));

        SsoSessionTtl ttlX = adapter.resolveTtl("tenant-x");
        SsoSessionTtl ttlY = adapter.resolveTtl("tenant-y");

        assertThat(ttlX.absolute()).isEqualTo(Duration.ofHours(2));
        assertThat(ttlX.idle()).isEqualTo(Duration.ofMinutes(5));

        assertThat(ttlY.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttlY.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }
}
