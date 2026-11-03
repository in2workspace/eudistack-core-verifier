package es.in2.vcverifier.shared.config;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

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
}
