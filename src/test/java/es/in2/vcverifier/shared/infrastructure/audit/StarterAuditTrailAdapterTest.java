package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.application.AuditPublisher;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditResult;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class StarterAuditTrailAdapterTest {

    private final AuditPublisher publisher = mock(AuditPublisher.class);
    private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
    private StarterAuditTrailAdapter adapter;

    @BeforeEach
    void setUp() {
        when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        adapter = new StarterAuditTrailAdapter(publisher, transactionManager);
    }

    @Test
    void stage_successEntry_handsTheFactToThePublisherAsSuccess() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.SYSTEM_AUTHENTICATED, "system-client:c1", Map.of("client_id", "c1"));

        // Act
        adapter.stage(entry);

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.SUCCESS, draft.getValue().result());
        assertNull(draft.getValue().reason());
        assertEquals("SystemAuthenticated", draft.getValue().fact().eventType());
        assertEquals("AuthenticateSystem", draft.getValue().fact().action());
        assertEquals("system-client:c1", draft.getValue().fact().resource());
        assertEquals(Map.of("client_id", "c1"), draft.getValue().fact().details());
        verifyNoInteractions(transactionManager);
    }

    @Test
    void stage_deniedEntry_keepsTheReason() {
        // Arrange
        AuditEntry entry = AuditEntry.forReason(AuditEventType.SYSTEM_AUTHENTICATED, "system-client:c1",
                "InvalidAttestation", Map.of());

        // Act
        adapter.stage(entry);

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.DENIED, draft.getValue().result());
        assertEquals("InvalidAttestation", draft.getValue().reason());
    }

    @Test
    void stage_publisherFails_propagatesTheError() {
        // Arrange
        doThrow(new IllegalStateException("no transaction")).when(publisher).stage(any());
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:s", Map.of());

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> adapter.stage(entry));
    }

    @Test
    void stageInNewTransaction_entry_opensATransactionOfItsOwnAroundTheStaging() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:s", Map.of());

        // Act
        adapter.stageInNewTransaction(entry);

        // Assert
        ArgumentCaptor<TransactionDefinition> definition = ArgumentCaptor.forClass(TransactionDefinition.class);
        verify(transactionManager).getTransaction(definition.capture());
        assertEquals(TransactionDefinition.PROPAGATION_REQUIRES_NEW, definition.getValue().getPropagationBehavior());
        verify(publisher).stage(any());
    }

    @Test
    void stageBestEffort_publisherFails_doesNotFailTheCaller() {
        // Arrange
        doThrow(new IllegalStateException("audit down")).when(publisher).stage(any());
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:s", Map.of());

        // Act & Assert
        assertDoesNotThrow(() -> adapter.stageBestEffort(entry));
    }

    @Test
    void asSystem_action_returnsItsResult() {
        // Arrange & Act
        String result = adapter.asSystem("platform", "verifier", () -> "result");

        // Assert
        assertEquals("result", result);
    }
}
