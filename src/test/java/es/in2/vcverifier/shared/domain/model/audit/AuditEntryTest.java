package es.in2.vcverifier.shared.domain.model.audit;

import es.in2.vcverifier.shared.domain.exception.InvalidAuditEntryException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditEntryTest {

    private static final String RESOURCE = "system-client:machine-1";

    @Test
    void success_withoutDetails_buildsEntryWithoutReason() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.success(AuditEventType.SYSTEM_AUTHENTICATED, RESOURCE, null);

        // Assert
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertNull(entry.reason());
        assertEquals(Map.of(), entry.details());
    }

    @Test
    void forReason_reasonOfTheDeniedVocabulary_derivesDenied() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.forReason(AuditEventType.SYSTEM_AUTHENTICATED, RESOURCE, "AttestationRevoked", Map.of());

        // Assert
        assertEquals(AuditResult.DENIED, entry.result());
    }

    @Test
    void forReason_reasonOfTheFailureVocabulary_derivesFailure() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, "Timeout", Map.of());

        // Assert
        assertEquals(AuditResult.FAILURE, entry.result());
    }

    @Test
    void forReason_reasonOfAnotherType_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class,
                () -> AuditEntry.forReason(AuditEventType.SYSTEM_AUTHENTICATED, RESOURCE, "Timeout", Map.of()));
    }

    @Test
    void constructor_failureWithAReasonThatDeterminesDenied_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class, () -> new AuditEntry(
                AuditEventType.SYSTEM_AUTHENTICATED, RESOURCE, AuditResult.FAILURE, "InvalidAttestation", Map.of()));
    }

    @Test
    void constructor_successWithReason_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class, () -> new AuditEntry(
                AuditEventType.SYSTEM_AUTHENTICATED, RESOURCE, AuditResult.SUCCESS, "InvalidAttestation", Map.of()));
    }

    @Test
    void constructor_blankResource_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class, () -> AuditEntry.success(AuditEventType.SYSTEM_AUTHENTICATED, " ", Map.of()));
    }

    @Test
    void success_withNullValues_omitsThemAtEveryLevel() {
        // Arrange
        Map<String, Object> nested = new HashMap<>();
        nested.put("kept", "value");
        nested.put("dropped", null);
        Map<String, Object> details = new HashMap<>();
        details.put("nested", nested);
        details.put("absent", null);
        details.put("list", List.of("a"));

        // Act
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, details);

        // Assert
        assertFalse(entry.details().containsKey("absent"));
        assertEquals(Map.of("kept", "value"), entry.details().get("nested"));
        assertEquals(List.of("a"), entry.details().get("list"));
    }
}
