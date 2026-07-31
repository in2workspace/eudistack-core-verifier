package es.in2.vcverifier.verifier.infrastructure.metrics;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class CredentialVerificationMetricsRecorderTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void recordVerifiedOk_registersCounterWithTags() {
        bindRequestWithTenant("kpmg");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        recorder.recordVerifiedOk("learcredential.employee.w3c.4");

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_TENANT, "kpmg",
                        CredentialVerificationMetricsRecorder.TAG_CONFIGURATION_ID, "learcredential.employee.w3c.4",
                        CredentialVerificationMetricsRecorder.TAG_OUTCOME, "ok")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void recordVerifiedError_tagsOutcomeError() {
        bindRequestWithTenant("kpmg");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        recorder.recordVerifiedError("learcredential.employee.w3c.4");

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_TENANT, "kpmg",
                        CredentialVerificationMetricsRecorder.TAG_CONFIGURATION_ID, "learcredential.employee.w3c.4",
                        CredentialVerificationMetricsRecorder.TAG_OUTCOME, "error")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void recordVerified_nullOrBlankConfigurationId_fallsBackToUnknown() {
        bindRequestWithTenant("kpmg");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        assertDoesNotThrow(() -> recorder.recordVerifiedOk(null));
        assertDoesNotThrow(() -> recorder.recordVerifiedOk("  "));

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_CONFIGURATION_ID, "unknown",
                        CredentialVerificationMetricsRecorder.TAG_OUTCOME, "ok")
                .counter().count()).isEqualTo(2.0);
    }

    @Test
    void recordVerified_noRequestBound_tenantFallsBackToUnknown() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        recorder.recordVerifiedOk("learcredential.employee.w3c.4");

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_TENANT, "unknown")
                .counter()).isNotNull();
    }

    @Test
    void recordVerified_resolvesTenantFromRequest() {
        bindRequestWithTenant("kpmg");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        recorder.recordVerifiedOk("learcredential.employee.w3c.4");

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_TENANT, "kpmg")
                .counter()).isNotNull();
    }

    @Test
    void recordVerified_twoVerifications_accumulate() {
        bindRequestWithTenant("kpmg");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(registry);

        recorder.recordVerifiedOk("learcredential.employee.w3c.4");
        recorder.recordVerifiedOk("learcredential.employee.w3c.4");

        assertThat(registry.get(CredentialVerificationMetricsRecorder.CREDENTIAL_VERIFIED)
                .tags(CredentialVerificationMetricsRecorder.TAG_CONFIGURATION_ID, "learcredential.employee.w3c.4",
                        CredentialVerificationMetricsRecorder.TAG_OUTCOME, "ok")
                .counter().count()).isEqualTo(2.0);
    }

    @Test
    void recordVerified_registryFailure_isNonBlocking() {
        MeterRegistry failing = mock(MeterRegistry.class);
        doThrow(new RuntimeException("registry down"))
                .when(failing).counter(anyString(), any(Iterable.class));

        CredentialVerificationMetricsRecorder recorder = new CredentialVerificationMetricsRecorder(failing);

        assertDoesNotThrow(() -> recorder.recordVerifiedOk("learcredential.employee.w3c.4"));
        assertDoesNotThrow(() -> recorder.recordVerifiedError("learcredential.employee.w3c.4"));
    }

    private void bindRequestWithTenant(String tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, tenant);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
