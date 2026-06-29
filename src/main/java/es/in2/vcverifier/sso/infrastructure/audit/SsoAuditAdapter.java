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

        // NFR-S-547-01: never log sub in clear — SHA-256 one-way hash, first 16 hex chars only
        logEvent.put("sub", maskSubject(event.getHolderHash()));

        // NFR-S-547-02: holderHash prefix for traceability (not a session id)
        logEvent.put("holderHashPrefix", prefix(event.getHolderHash()));

        log.info("SSO_AUDIT_EVENT {}", logEvent);
    }

    /**
     * Never expose subject (user identifier) in clear.
     * SHA-256 is used as a one-way hash; only the first 16 hex chars are logged
     * to limit exposure while retaining enough entropy for correlation.
     */
    private String maskSubject(String sub) {
        if (sub == null) return null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(sub.getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(hash);
            return hex.substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the JVM spec — this branch is unreachable in practice
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