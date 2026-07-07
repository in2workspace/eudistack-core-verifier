package es.in2.vcverifier.sso.domain.model;

import lombok.Data;
import java.time.Instant;

import lombok.Builder;
@Data
public class SsoAuditEvent {


    public enum EventType {
        SSO_SESSION_ESTABLISHED,
        SSO_ESTABLISH_FAILED,
        SSO_PERSIST_ERROR,
        SSO_CONFIG_INCONSISTENT,
        SSO_CROSS_TENANT_ATTEMPT,
        SSO_SESSION_REUSED,
        SSO_REUSE_DENIED,
        SSO_CATALOG_CLIENT_ADDED,
        SSO_CATALOG_CLIENT_REMOVED,
        // US-06 Single Logout (AC-06)
        SSO_LOGOUT_INITIATED,
        BACKCHANNEL_DELIVERED,
        BACKCHANNEL_FAILED,
        BACKCHANNEL_SKIPPED,
        SSO_LOGOUT_REJECTED,
        SSO_LOGOUT_STORE_ERROR,
    }

    private final EventType eventType;
    private final String tenant;
    private final String clientId;
    private final String holderHash;
    private final String outcome;
    private final String correlationId;
    private final Instant occurredAt;

    /**
     * US-06 (Single Logout): identificador de sesión SSO asociado al evento.
     * Nullable — solo los eventos del flujo de logout lo llevan. NFR-S-551-02:
     * el adapter de auditoría nunca lo loggea completo, solo un prefijo de 8 chars.
     */
    private final String sessionId;

    /**
     * Constructor legacy (pre-US-06): mantiene compatibilidad con los call sites
     * posicionales existentes (US-02/US-03/US-05). {@code sessionId} queda a {@code null}.
     */
    public SsoAuditEvent(
            EventType eventType,
            String tenant,
            String clientId,
            String holderHash,
            String outcome,
            String correlationId,
            Instant occurredAt
    ) {
        this(eventType, tenant, clientId, holderHash, outcome, correlationId, occurredAt, null);
    }

    @Builder
    public SsoAuditEvent(
            EventType eventType,
            String tenant,
            String clientId,
            String holderHash,
            String outcome,
            String correlationId,
            Instant occurredAt,
            String sessionId
    ) {
        this.eventType = eventType;
        this.tenant = tenant;
        this.clientId = clientId;
        this.holderHash = holderHash;
        this.outcome = outcome;
        this.correlationId = correlationId;
        this.occurredAt = occurredAt;
        this.sessionId = sessionId;
    }

}