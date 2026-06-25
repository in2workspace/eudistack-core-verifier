package es.in2.vcverifier.sso.domain.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.time.Instant;

@AllArgsConstructor
@Data
public class SsoAuditEvent {


    public enum EventType {
        SSO_SESSION_ESTABLISHED,
        SSO_ESTABLISH_FAILED,
        SSO_PERSIST_ERROR,
        SSO_CONFIG_INCONSISTENT,
        SSO_CROSS_TENANT_ATTEMPT
    }

    private final EventType eventType;
    private final String tenant;
    private final String clientId;
    private final String holderHash;
    private final String outcome;
    private final String correlationId;
    private final Instant occurredAt;
    /** NFR-S-547-02: first 8 chars of the session id, null when session was not created. */
    private final String sessionIdPrefix;

}