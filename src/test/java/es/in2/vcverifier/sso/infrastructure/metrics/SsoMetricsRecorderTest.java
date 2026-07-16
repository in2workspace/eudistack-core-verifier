package es.in2.vcverifier.sso.infrastructure.metrics;

import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class SsoMetricsRecorderTest {

    @Test
    void SsoMetricsRecorder_incrementsReuseAndAvoided() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        SsoMetricsRecorder recorder = new SsoMetricsRecorder(registry);

        recorder.recordEstablishment("tenantA");
        recorder.recordReuse("tenantA", "clientB");
        recorder.recordReuse("tenantA", "clientB");
        recorder.recordOid4vpAvoided("tenantA");

        double reuse = registry.get(SsoMetricsRecorder.REUSE_TOTAL)
                .tags(SsoMetricsRecorder.TAG_TENANT, "tenantA",
                        SsoMetricsRecorder.TAG_CLIENT_ID, "clientB")
                .counter().count();
        double avoided = registry.get(SsoMetricsRecorder.OID4VP_AVOIDED_TOTAL)
                .tags(SsoMetricsRecorder.TAG_TENANT, "tenantA")
                .counter().count();

        assertThat(reuse).isEqualTo(2.0);
        assertThat(avoided).isEqualTo(1.0);

        SsoTenantMetrics metrics = recorder.metricsFor("tenantA");
        assertThat(metrics.establishedTotal()).isEqualTo(1);
        assertThat(metrics.reuseTotal()).isEqualTo(2);
        assertThat(metrics.oid4vpAvoidedTotal()).isEqualTo(1);
        assertThat(metrics.reuseRatio()).isEqualTo(2.0);
        assertThat(metrics.byClientId().get("clientB").reuseTotal()).isEqualTo(2);
    }

    @Test
    void SsoMetricsRecorder_zeroActivity_noDivisionByZero() {
        SsoMetricsRecorder recorder = new SsoMetricsRecorder(new SimpleMeterRegistry());

        SsoTenantMetrics metrics = assertDoesNotThrow(() -> recorder.metricsFor("emptyTenant"));

        assertThat(metrics.establishedTotal()).isZero();
        assertThat(metrics.reuseTotal()).isZero();
        assertThat(metrics.oid4vpAvoidedTotal()).isZero();
        assertThat(metrics.reuseRatio()).isNull();
        assertThat(metrics.byClientId()).isEmpty();
    }

    @Test
    void SsoMetricsRecorder_registryFailure_isNonBlocking() {
        MeterRegistry failing = mock(MeterRegistry.class);
        doThrow(new RuntimeException("registry down"))
                .when(failing).counter(anyString(), any(Iterable.class));

        SsoMetricsRecorder recorder = new SsoMetricsRecorder(failing);

        assertDoesNotThrow(() -> recorder.recordEstablishment("tenantA"));
        assertDoesNotThrow(() -> recorder.recordReuse("tenantA", "clientB"));
        assertDoesNotThrow(() -> recorder.recordOid4vpAvoided("tenantA"));
    }
}
