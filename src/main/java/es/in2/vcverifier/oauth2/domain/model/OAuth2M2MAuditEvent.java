package es.in2.vcverifier.oauth2.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@AllArgsConstructor
@Data
@Builder
public class OAuth2M2MAuditEvent {

    private final String clientId;
    private final String tenant;
    private final String outcome;
    private final String reason;
    private final String correlationId;
    private final Instant occurredAt;

}
