package es.in2.vcverifier.oauth2.domain.audit;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SystemAuthenticationAuditEventsTest {

    private static OAuth2M2MAuditEvent event(String clientId, String outcome, String reason) {
        return OAuth2M2MAuditEvent.builder()
                .clientId(clientId)
                .tenant("dome")
                .outcome(outcome)
                .reason(reason)
                .correlationId("correlation-1")
                .occurredAt(Instant.now())
                .build();
    }

    @ParameterizedTest
    @CsvSource({
            "credential_type_not_eligible, InvalidAttestation, DENIED",
            "invalid_proof_of_possession, InvalidAttestation, DENIED",
            "issuer_not_trusted, InvalidAttestation, DENIED",
            "credential_expired, InvalidAttestation, DENIED",
            "credential_not_active, InvalidAttestation, DENIED",
            "credential_validation_failed, InvalidAttestation, DENIED",
            "tenant_mismatch, InvalidAttestation, DENIED",
            "tenant_not_derivable, InvalidAttestation, DENIED",
            "request_tenant_not_derivable, InvalidAttestation, DENIED",
            "credential_revoked, AttestationRevoked, DENIED",
            "external_dependency_failure, InternalError, FAILURE"
    })
    void of_rejectedAttempt_mapsTheInternalReasonToTheCatalogueReasonAndResult(
            String internalReason, String catalogueReason, AuditResult expectedResult) {
        // Arrange
        OAuth2M2MAuditEvent rejected = event("machine-1", "REJECT", internalReason);

        // Act
        Optional<AuditEntry> entry = SystemAuthenticationAuditEvents.of(rejected);

        // Assert
        assertEquals(catalogueReason, entry.orElseThrow().reason());
        assertEquals(expectedResult, entry.orElseThrow().result());
    }

    @Test
    void of_acceptedAttempt_isSuccessWithoutReasonAndCarriesTheClientId() {
        // Arrange & Act
        AuditEntry entry = SystemAuthenticationAuditEvents.of(event("machine-1", "ACCEPT", null)).orElseThrow();

        // Assert
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("machine-1", entry.details().get("client_id"));
        assertEquals("system-client:machine-1", entry.resource());
    }

    @Test
    void of_attemptWithoutClientId_isNotReportedBecauseThereIsNoSystemToPointAt() {
        // Arrange & Act
        Optional<AuditEntry> entry = SystemAuthenticationAuditEvents.of(event(null, "REJECT", "credential_expired"));

        // Assert
        assertTrue(entry.isEmpty());
    }

    @Test
    void of_unknownOutcome_isNotReported() {
        // Arrange & Act
        Optional<AuditEntry> entry = SystemAuthenticationAuditEvents.of(event("machine-1", "PENDING", null));

        // Assert
        assertTrue(entry.isEmpty());
    }
}
