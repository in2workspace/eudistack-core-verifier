package es.in2.vcverifier.shared.config;

import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.server.observation.DefaultServerRequestObservationConvention;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.stereotype.Component;

/**
 * Adds a {@code tenant} low-cardinality tag to the auto-configured
 * {@code http.server.requests} observation, so error-rate and latency can be
 * sliced per tenant. Registering this bean overrides Boot's default convention
 * ({@code @ConditionalOnMissingBean(ServerRequestObservationConvention.class)}).
 *
 * <p>{@link TenantDomainFilter} runs at {@code HIGHEST_PRECEDENCE + 10}, before
 * {@code ServerHttpObservationFilter} ({@code HIGHEST_PRECEDENCE + 1}) stops the
 * observation, so the request attribute it sets is already populated here.
 */
@Component
public class TenantServerRequestObservationConvention extends DefaultServerRequestObservationConvention {

    private static final String UNKNOWN_TENANT = "unknown";

    @Override
    public KeyValues getLowCardinalityKeyValues(ServerRequestObservationContext context) {
        return super.getLowCardinalityKeyValues(context).and(tenant(context));
    }

    private KeyValue tenant(ServerRequestObservationContext context) {
        HttpServletRequest request = context.getCarrier();
        String tenant = request != null ? TenantDomainFilter.getCurrentTenant(request) : null;
        return KeyValue.of("tenant", tenant == null || tenant.isBlank() ? UNKNOWN_TENANT : tenant);
    }
}
