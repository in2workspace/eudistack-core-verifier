package es.in2.vcverifier.sso.infrastructure.audit;

import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

@Component
@Slf4j
public class SsoAuditAdapter implements SsoAuditPort {

    private static final Set<SsoAuditEvent.EventType> CATALOG_EVENTS = Set.of(
            SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED,
            SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED,
            SsoAuditEvent.EventType.SSO_CATALOG_NO_OP
    );

    @Override
    public void publish(SsoAuditEvent event) {
        if (CATALOG_EVENTS.contains(event.getEventType())) {
            logCatalogChange(event);
            return;
        }

        Map<String, Object> logEvent = new HashMap<>();

        logEvent.put("eventType", event.getEventType().name());
        logEvent.put("tenant", event.getTenant());
        logEvent.put("clientId", event.getClientId());
        logEvent.put("outcome", event.getOutcome());
        logEvent.put("correlationId", event.getCorrelationId());
        logEvent.put("occurredAt", event.getOccurredAt());

        // NFR-S-547-01: never log sub in clear — SHA-256 one-way hash
        logEvent.put("sub", maskSubject(event.getHolderHash()));

        // NFR-S-547-02: holderHash prefix for traceability (not a session id)
        logEvent.put("holderHashPrefix", prefix(event.getHolderHash()));

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * Never expose subject (user identifier) in clear.
     */
    private String maskSubject(String sub) {
        if (sub == null) return null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(sub.getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(hash);
            return hex.substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            return "unavailable";
        }
    }

    /**
     * Only expose first 8 chars of holder hash prefix for traceability.
     */
    private String prefix(String holderHash) {
        if (holderHash == null) return null;
        return holderHash.length() <= 8
                ? holderHash
                : holderHash.substring(0, 8);
    }

    // =========================================================
    // NEW METHOD
    // =========================================================

    /**
     * NFR: Never expose full sessionId in logs.
     * Only prefix allowed for traceability.
     */
    private String prefixSessionId(String sessionId) {
        if (sessionId == null) return null;
        return sessionId.length() <= 8
                ? sessionId
                : sessionId.substring(0, 8);
    }

    // =========================================================
    // CATALOG CHANGE (NFR-O-01)
    // =========================================================

    /**
     * Emite un evento estructurado de tipo CATALOG_CHANGE (NFR-O-01).
     * No aplica masking de holderHash: los eventos de catálogo no contienen datos de usuario.
     */
    private void logCatalogChange(SsoAuditEvent event) {
        Map<String, Object> logEvent = new HashMap<>();
        logEvent.put("type", "CATALOG_CHANGE");
        logEvent.put("tenant", event.getTenant());
        logEvent.put("operation", toOperation(event.getEventType()));
        logEvent.put("clientId", event.getClientId());
        logEvent.put("timestamp", event.getOccurredAt());
        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    private String toOperation(SsoAuditEvent.EventType type) {
        return switch (type) {
            case SSO_CATALOG_CLIENT_ADDED   -> "ADD";
            case SSO_CATALOG_CLIENT_REMOVED -> "REMOVE";
            default                         -> "NO_OP";
        };
    }
}