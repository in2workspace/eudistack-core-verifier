package es.in2.vcverifier.sso.domain.model;

import java.time.Instant;
import java.util.Objects;

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

    public SsoAuditEvent(
            EventType eventType,
            String tenant,
            String clientId,
            String holderHash,
            String outcome,
            String correlationId,
            Instant occurredAt
    ) {
        this.eventType = Objects.requireNonNull(eventType);
        this.tenant = Objects.requireNonNull(tenant);
        this.clientId = clientId;
        this.holderHash = holderHash;
        this.outcome = outcome;
        this.correlationId = correlationId;
        this.occurredAt = occurredAt != null ? occurredAt : Instant.now();
    }

    public EventType getEventType() {
        return eventType;
    }

    public String getTenant() {
        return tenant;
    }

    public String getClientId() {
        return clientId;
    }

    public String getHolderHash() {
        return holderHash;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }








}
