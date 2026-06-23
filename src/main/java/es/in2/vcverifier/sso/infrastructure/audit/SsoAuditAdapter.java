package es.in2.vcverifier.sso.infrastructure.audit;

import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;


@Component
@Slf4j
public class SsoAuditAdapter implements SsoAuditPort {


    @Override
    public void publish(SsoAuditEvent event) {

        Map<String, Object> logEvent = new HashMap<>();

        logEvent.put("eventType", event.getEventType().name());
        logEvent.put("tenant", event.getTenant());
        logEvent.put("clientId", event.getClientId());
        logEvent.put("outcome", event.getOutcome());
        logEvent.put("correlationId", event.getCorrelationId());
        logEvent.put("occurredAt", event.getOccurredAt());

        // NFR-S-547-01: never log sub in clear
        logEvent.put("sub", maskSubject(event.getHolderHash()));

        // NFR-S-547-02: only prefix of session id
        logEvent.put("sessionId", prefix(event.getHolderHash()));

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * Never expose subject (user identifier) in clear.
     * We hash it for observability safety.
     */
    private String maskSubject(String sub) {
        if (sub == null) return null;
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sub.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // log only a short prefix to reduce correlatability
            return java.util.HexFormat.of().formatHex(digest, 0, 8);
        } catch (java.security.NoSuchAlgorithmException e) {
            return Integer.toHexString(sub.hashCode());
        }
    }

    /**
     * Only expose first 8 chars of session id.
     */
    private String prefix(String sessionId) {
        if (sessionId == null) return null;
        return sessionId.length() <= 8
                ? sessionId
                : sessionId.substring(0, 8);
    }

}
