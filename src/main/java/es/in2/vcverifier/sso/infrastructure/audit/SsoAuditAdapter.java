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
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@Slf4j
public class SsoAuditAdapter implements SsoAuditPort {

    private static final String UNKNOWN = "unknown";

    @Override
    public void publish(SsoAuditEvent event) {
        // NFR-O-01: eventos de catálogo emiten formato CATALOG_CHANGE con campo operation
        try {
            if (event == null) {
                log.error("SSO_AUDIT_EMISSION_FAILED reason=null_event");
                return;
            }

            if (event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                    || event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED) {
                emitCatalogChangeEvent(event);
                return;
            }

            if (event.getEventType() == SsoAuditEvent.EventType.EMERGENCY_REVOKE) {
                emitEmergencyRevokeEvent(event);
                return;
            }

            emitLifecycleEvent(event);
        } catch (Exception ex) {
            log.error("SSO_AUDIT_EMISSION_FAILED eventType={} correlationId={} error={}",
                    safeType(event), safeCorrelation(event), ex.getClass().getSimpleName());
        }
    }

    private void emitLifecycleEvent(SsoAuditEvent event) {
        Map<String, Object> logEvent = new HashMap<>();

        String tenant = defaultIfBlank(event.getTenant(), UNKNOWN);
        String outcome = defaultIfBlank(event.getOutcome(), UNKNOWN);

        if (isBlank(event.getTenant()) || isBlank(event.getOutcome())) {
            logEvent.put("anomaly", "missing_mandatory_field");
        }

        logEvent.put("eventType", event.getEventType().name());
        logEvent.put("tenant", tenant);
        logEvent.put("clientId", event.getClientId());
        logEvent.put("outcome", outcome);
        logEvent.put("correlationId", event.getCorrelationId());
        logEvent.put("occurredAt", event.getOccurredAt());

        if (event.getReason() != null) {
            logEvent.put("reason", event.getReason());
        }

        // NFR-S-547-01 / NFR-S-552-01: never log sub in clear — SHA-256 one-way hash
        logEvent.put("sub", maskSubject(event.getHolderHash()));

        // NFR-S-547-02: holderHash prefix for traceability (not a session id)
        logEvent.put("holderHashPrefix", prefix(event.getHolderHash()));

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * NFR-O-01: structured format for SSO catalog changes.
     * eventType=CATALOG_CHANGE, operation=ADD|REMOVE, tenant, clientId, timestamp.
     */
    private void emitCatalogChangeEvent(SsoAuditEvent event) {
        String operation = event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                ? "ADD"
                : "REMOVE";

        Map<String, Object> logEvent = new LinkedHashMap<>();
        logEvent.put("eventType", "CATALOG_CHANGE");
        logEvent.put("tenant",    event.getTenant());
        logEvent.put("operation", operation);
        logEvent.put("clientId",  event.getClientId());
        logEvent.put("timestamp", event.getOccurredAt());

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * Does not include the SSO cookie, sub or holderHash: the cut is tenant-wide and does not
     * reference any specific Holder.
     */
    private void emitEmergencyRevokeEvent(SsoAuditEvent event) {
        Map<String, Object> logEvent = new LinkedHashMap<>();
        logEvent.put("eventType",      "sso_emergency_revoke");
        logEvent.put("tenant",         event.getTenant());
        logEvent.put("countRevoked",   event.getCountRevoked());
        logEvent.put("correlationId",  event.getCorrelationId());
        logEvent.put("outcome",        event.getOutcome());
        logEvent.put("occurredAt",     event.getOccurredAt());

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

    // ─── helpers (ES-01 / ES-04) ─────────────────────────────────────────────

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String defaultIfBlank(String value, String fallback) {
        return isBlank(value) ? fallback : value;
    }

    private static String safeType(SsoAuditEvent event) {
        return event == null || event.getEventType() == null
                ? UNKNOWN
                : event.getEventType().name();
    }

    private static String safeCorrelation(SsoAuditEvent event) {
        return event == null ? UNKNOWN : defaultIfBlank(event.getCorrelationId(), UNKNOWN);
    }

}
