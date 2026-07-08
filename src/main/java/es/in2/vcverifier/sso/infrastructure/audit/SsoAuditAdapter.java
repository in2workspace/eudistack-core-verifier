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

    @Override
    public void publish(SsoAuditEvent event) {
        // NFR-O-01: eventos de catálogo emiten formato CATALOG_CHANGE con campo operation
        if (event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                || event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED) {
            emitCatalogChangeEvent(event);
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

        // US-06 / NFR-S-551-02: session_id nunca completo — solo prefijo 8 chars.
        // Solo lo llevan los eventos del flujo de logout; null en el resto (prefix(null) = null).
        logEvent.put("sessionIdPrefix", prefix(event.getSessionId()));

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * NFR-O-01: formato estructurado para cambios de catálogo SSO.
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

}