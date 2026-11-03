package es.in2.vcverifier.shared.config;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObservationConfig {

    private static final String MDC_TENANT_DOMAIN = "tenantDomain";
    private static final String TENANT_TAG = "tenant";
    private static final String UNKNOWN_TENANT = "unknown";

    /**
     * Registers the AOP aspect to enable the use of @Observed.
     * Spring Boot auto-configures and injects the base ObservationRegistry.
     */
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }

    /**
     * Tags every observation (spans and the metrics derived from it) with the component and tenant.
     * A tenant already on the observation stays: Micrometer applies the convention first, and
     * TenantServerRequestObservationConvention reads it from the request because the MDC is empty
     * by the time an HTTP observation stops.
     */
    @Bean
    public ObservationFilter globalObservationFilter() {
        return context -> {
            context.addLowCardinalityKeyValue(KeyValue.of("component", MicrometerMetricsConfig.COMPONENT));
            if (context.getLowCardinalityKeyValue(TENANT_TAG) == null) {
                context.addLowCardinalityKeyValue(KeyValue.of(TENANT_TAG, tenantTagValue(MDC.get(MDC_TENANT_DOMAIN))));
            }
            return context;
        };
    }

    /**
     * The tag value for a resolved tenant. TenantDomainFilter takes the first segment of the host, so
     * a request to an IP such as 127.0.0.1 resolves to "127", which is not a tenant.
     */
    static String tenantTagValue(String tenant) {
        boolean noTenant = tenant == null || tenant.isBlank() || tenant.chars().allMatch(Character::isDigit);
        return noTenant ? UNKNOWN_TENANT : tenant;
    }
}
