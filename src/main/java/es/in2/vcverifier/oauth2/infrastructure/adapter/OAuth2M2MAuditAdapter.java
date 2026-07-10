package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class OAuth2M2MAuditAdapter implements OAuth2M2MAuditPort {

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
    }

}
