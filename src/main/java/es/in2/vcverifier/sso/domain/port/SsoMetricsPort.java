package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;

public interface SsoMetricsPort {

    /**
     * Records a successful SSO session establishment (baseline for the reuse ratio, AC-07).
     */
    void recordEstablishment(String tenant);

    /**
     * Records an SSO session reuse by a specific application.
     */
    void recordReuse(String tenant, String clientId);

    /**
     * Records an OID4VP presentation avoided thanks to session reuse.
     */
    void recordOid4vpAvoided(String tenant);

    /**
     * Returns the snapshot of accumulated metrics for a tenant.
     */
    SsoTenantMetrics metricsFor(String tenant);

}
