package es.in2.vcverifier.sso;

import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.infrastructure.metrics.SsoMetricsRecorder;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {SsoMetricsRecorder.class, SsoMetricsIT.MetricsTestConfig.class})
class SsoMetricsIT {

    @Autowired
    private SsoMetricsPort metricsPort;

    @Autowired
    private MeterRegistry registry;

    @Test
    void reuseActivity_incrementsCanonicalCounters() {
        metricsPort.recordEstablishment("tenantA");
        metricsPort.recordReuse("tenantA", "clientB");
        metricsPort.recordReuse("tenantA", "clientB");
        metricsPort.recordReuse("tenantA", "clientC");
        metricsPort.recordOid4vpAvoided("tenantA");
        metricsPort.recordOid4vpAvoided("tenantA");
        metricsPort.recordOid4vpAvoided("tenantA");

        double reuseB = registry.get("verifier_sso_reuse_total")
                .tags("tenant", "tenantA", "client_id", "clientB")
                .counter().count();
        double reuseC = registry.get("verifier_sso_reuse_total")
                .tags("tenant", "tenantA", "client_id", "clientC")
                .counter().count();
        double avoided = registry.get("verifier_sso_oid4vp_avoided_total")
                .tags("tenant", "tenantA")
                .counter().count();

        assertThat(reuseB).isEqualTo(2.0);
        assertThat(reuseC).isEqualTo(1.0);
        assertThat(avoided).isEqualTo(3.0);

        SsoTenantMetrics metrics = metricsPort.metricsFor("tenantA");
        assertThat(metrics.establishedTotal()).isEqualTo(1);
        assertThat(metrics.reuseTotal()).isEqualTo(3);
        assertThat(metrics.oid4vpAvoidedTotal()).isEqualTo(3);
        assertThat(metrics.reuseRatio()).isEqualTo(3.0);
        assertThat(metrics.byClientId().get("clientB").reuseTotal()).isEqualTo(2);
        assertThat(metrics.byClientId().get("clientC").reuseTotal()).isEqualTo(1);
    }

    @Configuration
    static class MetricsTestConfig {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }
}
