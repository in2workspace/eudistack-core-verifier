package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.audit.SystemAuthenticationAuditEvents;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class OAuth2M2MAuditAdapter implements OAuth2M2MAuditPort {

    private final AuditTrailPort auditTrail;

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
        Runnable staging = entry.result() == AuditResult.SUCCESS
                ? () -> auditTrail.stageInNewTransaction(entry)
                : () -> auditTrail.stageBestEffort(entry);
        if (event.getCorrelationId() == null || event.getCorrelationId().isBlank()) {
            staging.run();
            return;
        }
        auditTrail.runWithCorrelationId(event.getCorrelationId(), staging);
    }

}
