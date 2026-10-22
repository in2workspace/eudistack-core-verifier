package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.RecordingAuditTrail;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2M2MAuditAdapterTest {

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final OAuth2M2MAuditAdapter adapter = new OAuth2M2MAuditAdapter(auditTrail);

    private static OAuth2M2MAuditEvent event(String clientId, String outcome, String reason, String correlationId) {
        return OAuth2M2MAuditEvent.builder()
                .clientId(clientId)
                .tenant("dome")
                .outcome(outcome)
                .reason(reason)
                .correlationId(correlationId)
                .occurredAt(Instant.now())
                .build();
    }

    @Test
    void publish_acceptOutcome_doesNotThrow() {
        OAuth2M2MAuditEvent event = event("unregistered-machine-client", "ACCEPT", null, UUID.randomUUID().toString());

        assertDoesNotThrow(() -> adapter.publish(event));
    }

    @Test
    void publish_rejectOutcomeWithReason_doesNotThrow() {
        OAuth2M2MAuditEvent event = event("unregistered-machine-client", "REJECT", "tenant_mismatch", UUID.randomUUID().toString());

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

    @Test
    void publish_acceptedSystem_stagesSystemAuthenticatedSuccessUnderTheCorrelationOfTheAttempt() {
        // Arrange
        String correlationId = UUID.randomUUID().toString();

        // Act
        adapter.publish(event("machine-1", "ACCEPT", null, correlationId));

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.SYSTEM_AUTHENTICATED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("system-client:machine-1", entry.resource());
        assertEquals("machine-1", entry.details().get("client_id"));
        assertEquals(List.of(correlationId), auditTrail.correlationIds());
    }

    @Test
    void publish_rejectedSystem_stagesSystemAuthenticatedDeniedInvalidAttestation() {
        // Arrange & Act
        adapter.publish(event("machine-1", "REJECT", "invalid_proof_of_possession", UUID.randomUUID().toString()));

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.DENIED, entry.result());
        assertEquals("InvalidAttestation", entry.reason());
    }

    @Test
    void publish_rejectedWithUnknownInternalReason_stagesNothingInsteadOfInventingOne() {
        // Arrange & Act
        adapter.publish(event("machine-1", "REJECT", "some_new_internal_reason", UUID.randomUUID().toString()));

        // Assert
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void publish_stagingFails_stillCompletesBecauseTheAuthenticationAttemptMustNotDependOnTheAudit() {
        // Arrange
        OAuth2M2MAuditAdapter brokenAdapter = new OAuth2M2MAuditAdapter(new RecordingAuditTrail().failingOnNewTransaction());
        OAuth2M2MAuditEvent event = event("machine-1", "ACCEPT", null, UUID.randomUUID().toString());

        // Act & Assert
        assertDoesNotThrow(() -> brokenAdapter.publish(event));
    }
}
