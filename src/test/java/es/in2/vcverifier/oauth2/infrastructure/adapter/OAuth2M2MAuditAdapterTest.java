package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.RecordingAuditTrail;
import es.in2.vcverifier.shared.infrastructure.audit.RejectionThrottle;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2M2MAuditAdapterTest {

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final OAuth2M2MAuditAdapter adapter = new OAuth2M2MAuditAdapter(auditTrail, new RejectionThrottle());

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
    void publish_acceptedSystem_stagesSystemAuthenticatedSuccessWithTheSystemAsTheActorInItsTenant() {
        // Arrange & Act
        adapter.publish(event("machine-1", "ACCEPT", null, UUID.randomUUID().toString()));

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.SYSTEM_AUTHENTICATED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("system-client:machine-1", entry.resource());
        assertEquals("machine-1", entry.details().get("client_id"));
        assertEquals(List.of("dome/machine-1"), auditTrail.systemScopes());
    }

    @Test
    void publish_acceptedWithoutATenant_stagesInTheContextOfTheRequest() {
        // Arrange
        OAuth2M2MAuditEvent withoutTenant = OAuth2M2MAuditEvent.builder().clientId("machine-1").tenant(null)
                .outcome("ACCEPT").occurredAt(Instant.now()).build();

        // Act
        adapter.publish(withoutTenant);

        // Assert
        assertEquals(1, auditTrail.stagedInNewTransaction().size());
        assertTrue(auditTrail.systemScopes().isEmpty());
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
    void publish_acceptedAndStagingFails_failsSoNoTokenLeavesWithoutItsTrace() {
        // Arrange
        OAuth2M2MAuditAdapter brokenAdapter = new OAuth2M2MAuditAdapter(new RecordingAuditTrail().failingOnNewTransaction(), new RejectionThrottle());
        OAuth2M2MAuditEvent event = event("machine-1", "ACCEPT", null, UUID.randomUUID().toString());

        // Act
        OAuth2AuthenticationException error = assertThrows(OAuth2AuthenticationException.class,
                () -> brokenAdapter.publish(event));

        // Assert: the client is told the server failed, and nothing of the event travels in the error
        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, error.getError().getErrorCode());
        assertNull(error.getError().getDescription());
    }

    @Test
    void publish_rejectedAndStagingFails_stillCompletesBecauseNoTokenIsIssuedAnyway() {
        // Arrange
        OAuth2M2MAuditAdapter brokenAdapter = new OAuth2M2MAuditAdapter(new RecordingAuditTrail().failingOnNewTransaction(), new RejectionThrottle());
        OAuth2M2MAuditEvent event = event("machine-1", "REJECT", "invalid_proof_of_possession", UUID.randomUUID().toString());

        // Act & Assert
        assertDoesNotThrow(() -> brokenAdapter.publish(event));
    }

    @Test
    void publish_manyRefusalsOfTheSameClient_stagesOnlyTheFirstFew() {
        // Arrange & Act
        for (int i = 0; i < 50; i++) {
            adapter.publish(event("machine-1", "REJECT", "invalid_proof_of_possession", UUID.randomUUID().toString()));
        }

        // Assert
        assertEquals(RejectionThrottle.MAX_PER_KEY, auditTrail.stagedInNewTransaction().size());
    }

    @Test
    void publish_manyRefusalsOfDifferentClients_areCappedInTotal() {
        // Arrange & Act
        for (int i = 0; i < 1_000; i++) {
            adapter.publish(event("machine-" + i, "REJECT", "invalid_proof_of_possession", UUID.randomUUID().toString()));
        }

        // Assert
        assertEquals(RejectionThrottle.MAX_IN_TOTAL, auditTrail.stagedInNewTransaction().size());
    }

    @Test
    void publish_refusalOfAnOversizedOrMalformedClientId_stagesNothing() {
        // Arrange & Act
        adapter.publish(event("x".repeat(300), "REJECT", "invalid_proof_of_possession", null));
        adapter.publish(event("machine\n<script>", "REJECT", "invalid_proof_of_possession", null));

        // Assert
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void publish_acceptedDoesNotCountAgainstTheRefusalLimit() {
        // Arrange & Act
        for (int i = 0; i < 20; i++) {
            adapter.publish(event("machine-1", "ACCEPT", null, null));
        }

        // Assert
        assertEquals(20, auditTrail.stagedInNewTransaction().size());
    }
}
