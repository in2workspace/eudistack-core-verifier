package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SsoTenantMetricsTest {

    @Test
    void of_computesReuseRatio_whenEstablishmentsExist() {
        SsoTenantMetrics metrics = SsoTenantMetrics.of("tenantA", 100, 250, 250, Map.of());

        assertThat(metrics.establishedTotal()).isEqualTo(100);
        assertThat(metrics.reuseTotal()).isEqualTo(250);
        assertThat(metrics.oid4vpAvoidedTotal()).isEqualTo(250);
        assertThat(metrics.reuseRatio()).isEqualTo(2.5);
    }

    @Test
    void of_returnsNullRatio_whenNoEstablishments() {
        SsoTenantMetrics metrics = SsoTenantMetrics.of("tenantA", 0, 0, 0, Map.of());

        assertThat(metrics.reuseRatio()).isNull();
    }

    @Test
    void of_returnsNullRatio_whenReuseWithoutEstablishment() {
        SsoTenantMetrics metrics = SsoTenantMetrics.of("tenantA", 0, 5, 5, Map.of());

        assertThat(metrics.reuseRatio()).isNull();
    }

    @Test
    void of_preservesClientBreakdown() {
        Map<String, SsoTenantMetrics.ClientReuseMetrics> byClient = Map.of(
                "app-a", new SsoTenantMetrics.ClientReuseMetrics("app-a", 100),
                "app-b", new SsoTenantMetrics.ClientReuseMetrics("app-b", 150));

        SsoTenantMetrics metrics = SsoTenantMetrics.of("tenantA", 100, 250, 250, byClient);

        assertThat(metrics.byClientId())
                .containsKeys("app-a", "app-b");
        assertThat(metrics.byClientId().get("app-b").reuseTotal()).isEqualTo(150);
    }
}
