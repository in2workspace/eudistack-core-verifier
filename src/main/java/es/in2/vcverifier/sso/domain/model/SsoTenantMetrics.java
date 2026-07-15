package es.in2.vcverifier.sso.domain.model;

import java.util.Map;

public record SsoTenantMetrics(
        String tenant,
        long establishedTotal,
        long reuseTotal,
        long oid4vpAvoidedTotal,
        Double reuseRatio,
        Map<String, ClientReuseMetrics> byClientId
) {

    public SsoTenantMetrics {
        byClientId = byClientId == null ? Map.of() : Map.copyOf(byClientId);
    }

    public record ClientReuseMetrics(String clientId, long reuseTotal) {}

    public static SsoTenantMetrics of(
            String tenant,
            long establishedTotal,
            long reuseTotal,
            long oid4vpAvoidedTotal,
            Map<String, ClientReuseMetrics> byClientId
    ) {
        Double ratio = establishedTotal == 0
                ? null
                : (double) reuseTotal / establishedTotal;
        return new SsoTenantMetrics(
                tenant, establishedTotal, reuseTotal, oid4vpAvoidedTotal, ratio, byClientId);
    }

}
