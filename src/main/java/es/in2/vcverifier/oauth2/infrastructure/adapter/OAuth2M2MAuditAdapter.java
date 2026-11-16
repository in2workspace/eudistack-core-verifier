package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.audit.SystemAuthenticationAuditEvents;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import es.in2.vcverifier.shared.infrastructure.audit.RejectionThrottle;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class OAuth2M2MAuditAdapter implements OAuth2M2MAuditPort {

    private final AuditTrailPort auditTrail;
    private final RejectionThrottle rejectionThrottle;

    @Override
    public void publish(OAuth2M2MAuditEvent event) {

        Map<String, Object> logEvent = new HashMap<>();

        logEvent.put("clientId", event.getClientId());
        logEvent.put("tenant", event.getTenant());
        logEvent.put("outcome", event.getOutcome());
        logEvent.put("reason", event.getReason());
        logEvent.put("correlationId", event.getCorrelationId());
        logEvent.put("occurredAt", event.getOccurredAt());

        log.info("OAUTH2_M2M_AUDIT_EVENT {}", logEvent);

        SystemAuthenticationAuditEvents.of(event).ifPresent(entry -> stage(event, entry));
    }

    private void stage(OAuth2M2MAuditEvent event, AuditEntry entry) {
        // A token must not leave without its trace (DT-002 FR-09, EC-10): an accepted authentication is staged
        // reliably, so a failed insert fails the request and no token is issued. A rejection issues nothing, so
        // a broken audit channel must not turn it into a server error.
        if (entry.result() == AuditResult.SUCCESS) {
            stageAccepted(event, entry);
            return;
        }
        // Anyone can be refused, and the client id is whatever they wrote: bounded, not one row per request.
        if (rejectionThrottle.allow(event.getTenant() + "|" + event.getClientId() + "|" + event.getReason())) {
            auditTrail.stageBestEffort(entry);
        }
    }

    /**
     * The attestation was validated, so the system is who it says it is: it is the actor, in the tenant it was
     * accepted for.
     */
    private void stageAccepted(OAuth2M2MAuditEvent event, AuditEntry entry) {
        try {
            if (event.getTenant() == null || event.getTenant().isBlank()) {
                auditTrail.stageInNewTransaction(entry);
                return;
            }
            auditTrail.asSystem(event.getTenant(), event.getClientId(), () -> {
                auditTrail.stageInNewTransaction(entry);
                return null;
            });
        } catch (RuntimeException _) {
            // Nothing of the event goes into the error: the adapter has already reported the failure.
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
        }
    }

}
