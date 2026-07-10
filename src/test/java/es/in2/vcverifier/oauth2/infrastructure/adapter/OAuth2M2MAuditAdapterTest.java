package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class OAuth2M2MAuditAdapterTest {

    private final OAuth2M2MAuditAdapter adapter = new OAuth2M2MAuditAdapter();

    @Test
    void publish_acceptOutcome_doesNotThrow() {
        OAuth2M2MAuditEvent event = OAuth2M2MAuditEvent.builder()
                .clientId("unregistered-machine-client")
                .tenant("dome")
                .outcome("ACCEPT")
                .reason(null)
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .build();

        assertDoesNotThrow(() -> adapter.publish(event));
    }

    @Test
    void publish_rejectOutcomeWithReason_doesNotThrow() {
        OAuth2M2MAuditEvent event = OAuth2M2MAuditEvent.builder()
                .clientId("unregistered-machine-client")
                .tenant("dome")
                .outcome("REJECT")
                .reason("tenant_mismatch")
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .build();

        assertDoesNotThrow(() -> adapter.publish(event));
    }

    @Test
    void publish_nullClientIdAndTenant_doesNotThrowNpe() {
        OAuth2M2MAuditEvent event = OAuth2M2MAuditEvent.builder()
                .clientId(null)
                .tenant(null)
                .outcome("REJECT")
                .reason("credential_validation_failed")
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .build();

        assertDoesNotThrow(() -> adapter.publish(event));
    }
}
