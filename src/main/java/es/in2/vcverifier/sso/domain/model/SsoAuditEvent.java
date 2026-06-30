package es.in2.vcverifier.sso.domain.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.time.Instant;

import lombok.Builder;
@AllArgsConstructor
@Data
@Builder
public class SsoAuditEvent {


    public enum EventType {
        SSO_SESSION_ESTABLISHED,
        SSO_ESTABLISH_FAILED,
        SSO_PERSIST_ERROR,
        SSO_CONFIG_INCONSISTENT,
        SSO_CROSS_TENANT_ATTEMPT,
        SSO_SESSION_REUSED,
        SSO_CATALOG_CLIENT_ADDED,
        SSO_CATALOG_CLIENT_REMOVED,
        SSO_CATALOG_NO_OP,
    }

    private final EventType eventType;
    private final String tenant;
    private final String clientId;
    private final String holderHash;
    private final String outcome;
    private final String correlationId;
    private final Instant occurredAt;

}