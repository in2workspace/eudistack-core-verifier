package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.sso.application.command.RevokeTenantSessionsCommand;
import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.exception.TenantRevocationException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RevokeTenantSessionsWorkflowTest {

    private static final String TENANT = "tenant-1";
    private static final String CORRELATION_ID = "corr-id-001";
    private static final Instant NOW = Instant.parse("2026-07-08T10:00:00Z");

    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private SsoAuditPort auditPort;

    private RevokeTenantSessionsWorkflow workflow;

    @BeforeEach
    void setUp() {
        Clock fixedClock = Clock.fixed(NOW, ZoneOffset.UTC);
        workflow = new RevokeTenantSessionsWorkflow(sessionRepositoryPort, auditPort, fixedClock);
    }

    @Test
    void should_revoke_all_sessions_and_audit_success_when_sessions_exist() {
        // Given
        when(sessionRepositoryPort.revokeAllByTenant(TENANT)).thenReturn(5);

        // When
        int revoked = workflow.execute(new RevokeTenantSessionsCommand(TENANT, CORRELATION_ID));

        // Then
        assertThat(revoked).isEqualTo(5);

        SsoAuditEvent event = capturePublishedEvent();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.EMERGENCY_REVOKE);
        assertThat(event.getTenant()).isEqualTo(TENANT);
        assertThat(event.getCountRevoked()).isEqualTo(5);
        assertThat(event.getOutcome()).isEqualTo("success");
        assertThat(event.getCorrelationId()).isEqualTo(CORRELATION_ID);
        assertThat(event.getOccurredAt()).isEqualTo(NOW);
    }

    @Test
    void should_be_noop_and_audit_success_when_no_sessions() {
        // Given
        when(sessionRepositoryPort.revokeAllByTenant(TENANT)).thenReturn(0);

        // When
        int revoked = workflow.execute(new RevokeTenantSessionsCommand(TENANT, CORRELATION_ID));

        // Then
        assertThat(revoked).isZero();

        SsoAuditEvent event = capturePublishedEvent();
        assertThat(event.getCountRevoked()).isZero();
        assertThat(event.getOutcome()).isEqualTo("success");
    }

    @Test
    void should_audit_failure_and_throw_when_repository_fails() {
        // Given
        SsoSessionRepositoryException cause =
                new SsoSessionRepositoryException("bulk delete failed");
        when(sessionRepositoryPort.revokeAllByTenant(TENANT)).thenThrow(cause);

        // When / Then
        assertThatThrownBy(() ->
                workflow.execute(new RevokeTenantSessionsCommand(TENANT, CORRELATION_ID)))
                .isInstanceOf(TenantRevocationException.class)
                .hasCause(cause)
                .extracting(ex -> ((TenantRevocationException) ex).getCorrelationId())
                .isEqualTo(CORRELATION_ID);

        SsoAuditEvent event = capturePublishedEvent();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.EMERGENCY_REVOKE);
        assertThat(event.getOutcome()).isEqualTo("failure");
        assertThat(event.getCountRevoked()).isZero();
        assertThat(event.getCorrelationId()).isEqualTo(CORRELATION_ID);
    }

    @Test
    void should_reject_null_command() {
        // When / Then
        assertThatThrownBy(() -> workflow.execute(null))
                .isInstanceOf(NullPointerException.class);
        verifyNoInteractions(sessionRepositoryPort, auditPort);
    }

    private SsoAuditEvent capturePublishedEvent() {
        ArgumentCaptor<SsoAuditEvent> captor = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(auditPort).publish(captor.capture());
        return captor.getValue();
    }
}
