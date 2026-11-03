package es.in2.vcverifier.shared.config;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ObservationConfigTest {

    private final ObservationConfig config = new ObservationConfig();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void globalObservationFilter_AnyObservation_AddsTheComponentTag() {
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("component"))
                .isEqualTo(KeyValue.of("component", "verifier-backend"));
    }

    @Test
    void globalObservationFilter_TenantInMdc_AddsTheTenantTag() {
        MDC.put("tenantDomain", "sandbox");
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "sandbox"));
    }

    @Test
    void globalObservationFilter_NoTenantInMdc_AddsTheUnknownTenantTag() {
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "unknown"));
    }

    @Test
    void globalObservationFilter_IpHostInMdc_AddsTheUnknownTenantTag() {
        MDC.put("tenantDomain", "127");
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "unknown"));
    }

    @Test
    void globalObservationFilter_TenantWithDigitsInMdc_AddsTheTenantTag() {
        MDC.put("tenantDomain", "tenant-123");
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "tenant-123"));
    }

    @Test
    void globalObservationFilter_HttpObservationAfterTheMdcIsCleared_KeepsTheConventionTenant() {
        assertThat(stoppedHttpObservationTenant("sandbox")).isEqualTo("sandbox");
    }

    @Test
    void globalObservationFilter_HttpObservationWithoutTenant_ReportsTheUnknownTenant() {
        assertThat(stoppedHttpObservationTenant(null)).isEqualTo("unknown");
    }

    @Test
    void globalObservationFilter_HttpObservationFromAnIpHost_ReportsTheUnknownTenant() {
        assertThat(stoppedHttpObservationTenant("127")).isEqualTo("unknown");
    }

    /** Runs the real convention and filter in the order Micrometer applies them when an observation stops. */
    private String stoppedHttpObservationTenant(String requestTenant) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/verifier/api");
        if (requestTenant != null) {
            request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, requestTenant);
        }
        ServerRequestObservationContext context =
                new ServerRequestObservationContext(request, new MockHttpServletResponse());
        AtomicReference<String> tenant = new AtomicReference<>();
        ObservationRegistry registry = ObservationRegistry.create();
        registry.observationConfig().observationFilter(config.globalObservationFilter());
        registry.observationConfig().observationHandler(new ObservationHandler<>() {
            @Override
            public boolean supportsContext(Observation.Context ignored) {
                return true;
            }

            @Override
            public void onStop(Observation.Context stopped) {
                tenant.set(stopped.getLowCardinalityKeyValue("tenant").getValue());
            }
        });

        Observation.createNotStarted(new TenantServerRequestObservationConvention(), () -> context, registry)
                .start()
                .stop();

        return tenant.get();
    }
}
