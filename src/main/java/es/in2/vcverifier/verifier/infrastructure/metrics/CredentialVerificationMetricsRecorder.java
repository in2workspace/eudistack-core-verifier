package es.in2.vcverifier.verifier.infrastructure.metrics;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationMetricsPort;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.concurrent.atomic.AtomicBoolean;

@Component
@Slf4j
public class CredentialVerificationMetricsRecorder implements CredentialVerificationMetricsPort {

    static final String CREDENTIAL_VERIFIED = "business.credential.verified";
    static final String TAG_TENANT = "tenant";
    static final String TAG_CONFIGURATION_ID = "configuration_id";
    static final String TAG_OUTCOME = "outcome";
    static final String OUTCOME_OK = "ok";
    static final String OUTCOME_ERROR = "error";

    private static final String UNKNOWN = "unknown";

    private final MeterRegistry meterRegistry;
    private final AtomicBoolean failureLogged = new AtomicBoolean(false);

    public CredentialVerificationMetricsRecorder(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void recordVerifiedOk(String configurationId) {
        safelyIncrement(configurationId, OUTCOME_OK);
    }

    @Override
    public void recordVerifiedError(String configurationId) {
        safelyIncrement(configurationId, OUTCOME_ERROR);
    }

    private void safelyIncrement(String configurationId, String outcome) {
        try {
            meterRegistry.counter(CREDENTIAL_VERIFIED, Tags.of(
                    TAG_TENANT, safe(resolveTenantDomain()),
                    TAG_CONFIGURATION_ID, safe(configurationId),
                    TAG_OUTCOME, outcome)).increment();
        } catch (Exception ex) {
            logFailureOnce(ex);
        }
    }

    private String resolveTenantDomain() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attributes == null ? null : TenantDomainFilter.getCurrentTenant(attributes.getRequest());
        } catch (Exception ex) {
            log.debug("Unable to resolve tenant domain from request context. Falling back to unknown", ex);
            return null;
        }
    }

    private void logFailureOnce(Exception ex) {
        if (failureLogged.compareAndSet(false, true)) {
            log.warn("CREDENTIAL_VERIFICATION_METRICS_UNAVAILABLE error={} — instrumentation degraded (non-blocking)",
                    ex.getClass().getSimpleName());
        }
    }

    private static String safe(String value) {
        return (value == null || value.isBlank()) ? UNKNOWN : value;
    }
}
