package es.in2.vcverifier.sso.infrastructure.metrics;

import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
@Slf4j
public class SsoMetricsRecorder implements SsoMetricsPort {

    static final String REUSE_TOTAL = "verifier_sso_reuse_total";
    static final String OID4VP_AVOIDED_TOTAL = "verifier_sso_oid4vp_avoided_total";
    static final String ESTABLISHED_TOTAL = "verifier_sso_established_total";
    static final String TAG_TENANT = "tenant";
    static final String TAG_CLIENT_ID = "client_id";

    private static final String UNKNOWN = "unknown";

    private final MeterRegistry meterRegistry;
    private final AtomicBoolean failureLogged = new AtomicBoolean(false);

    public SsoMetricsRecorder(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void recordEstablishment(String tenant) {
        safelyIncrement(ESTABLISHED_TOTAL, Tags.of(TAG_TENANT, safe(tenant)));
    }

    @Override
    public void recordReuse(String tenant, String clientId) {
        safelyIncrement(REUSE_TOTAL, Tags.of(TAG_TENANT, safe(tenant), TAG_CLIENT_ID, safe(clientId)));
    }

    @Override
    public void recordOid4vpAvoided(String tenant) {
        safelyIncrement(OID4VP_AVOIDED_TOTAL, Tags.of(TAG_TENANT, safe(tenant)));
    }

    @Override
    public SsoTenantMetrics metricsFor(String tenant) {
        String scopedTenant = safe(tenant);
        try {
            long established = totalFor(ESTABLISHED_TOTAL, scopedTenant);
            long reuse = totalFor(REUSE_TOTAL, scopedTenant);
            long avoided = totalFor(OID4VP_AVOIDED_TOTAL, scopedTenant);
            Map<String, SsoTenantMetrics.ClientReuseMetrics> byClientId = reuseByClient(scopedTenant);
            return SsoTenantMetrics.of(scopedTenant, established, reuse, avoided, byClientId);
        } catch (Exception ex) {
            logFailureOnce(ex);
            return SsoTenantMetrics.of(scopedTenant, 0, 0, 0, Map.of());
        }
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    private void safelyIncrement(String name, Tags tags) {
        try {
            meterRegistry.counter(name, tags).increment();
        } catch (Exception ex) {
            logFailureOnce(ex);
        }
    }

    private long totalFor(String name, String tenant) {
        return (long) meterRegistry.find(name).tag(TAG_TENANT, tenant).counters()
                .stream()
                .mapToDouble(Counter::count)
                .sum();
    }

    private Map<String, SsoTenantMetrics.ClientReuseMetrics> reuseByClient(String tenant) {
        Map<String, SsoTenantMetrics.ClientReuseMetrics> byClientId = new LinkedHashMap<>();
        for (Counter counter : meterRegistry.find(REUSE_TOTAL).tag(TAG_TENANT, tenant).counters()) {
            String clientId = counter.getId().getTag(TAG_CLIENT_ID);
            if (clientId == null) {
                continue;
            }
            long count = (long) counter.count();
            byClientId.merge(
                    clientId,
                    new SsoTenantMetrics.ClientReuseMetrics(clientId, count),
                    (a, b) -> new SsoTenantMetrics.ClientReuseMetrics(clientId, a.reuseTotal() + b.reuseTotal()));
        }
        return byClientId;
    }

    private void logFailureOnce(Exception ex) {
        if (failureLogged.compareAndSet(false, true)) {
            log.warn("SSO_METRICS_UNAVAILABLE error={} — instrumentation degraded (non-blocking)",
                    ex.getClass().getSimpleName());
        }
    }

    private static String safe(String value) {
        return (value == null || value.isBlank()) ? UNKNOWN : value;
    }

}
