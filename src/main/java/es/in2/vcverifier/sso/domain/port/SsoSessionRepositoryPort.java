package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;

import java.util.Optional;
import java.time.Instant;

public interface SsoSessionRepositoryPort {

    /**
     * Persists the full aggregate.
     * @param session
     * @return
     */
    SsoSession save(SsoSession session);


    /**
     * Retrieves an active session for a specific tenant and holder.
     * @param tenant
     * @param holderHash
     * @return
     */
    Optional<SsoSession> findActiveByTenantAndHolder(
            String tenant,
            String holderHash
    );


    /**
     * Closes an active session in the DB.
     * @param tenant
     * @param holderHash
     */
    void supersedeActive(
            String tenant,
            String holderHash
    );

    /**
     * Retrieves an active session by its identifier and tenant.
     */
    Optional<SsoSession> findActiveById(
            SsoSessionId sessionId,
            String tenant
    );

    /**
     * Updates the last-used timestamp of an active session.
     */
    void updateLastUsedAt(
            SsoSessionId sessionId,
            String tenant,
            Instant now
    );

    /**
     * Finds a session by ID without a tenant filter.
     * Used exclusively to detect cross-tenant access attempts (AC-04).
     */
    Optional<SsoSession> findById(SsoSessionId sessionId);

    /**
     * Emergency cut: deletes in a single atomic operation all SSO sessions
     * of the given tenant (EUDISTACK-554 / US-09).
     *
     * @param tenantId tenant whose sessions are revoked (derived from the authenticated admin context)
     * @return number of deleted sessions ({@code count_revoked})
     */
    int revokeAllByTenant(String tenantId);

}
