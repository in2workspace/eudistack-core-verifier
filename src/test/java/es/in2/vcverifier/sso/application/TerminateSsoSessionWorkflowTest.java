package es.in2.vcverifier.sso.application;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.sso.application.command.TerminateSsoSessionCommand;
import es.in2.vcverifier.sso.domain.model.DeliveryOutcome;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.port.BackChannelLogoutNotifierPort;
import es.in2.vcverifier.sso.domain.port.BackchannelLogoutUriPort;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * US-06 (Single Logout): {@code TerminateSsoSessionWorkflow} — orquestación con puertos
 * mockeados. AD-3 (orden estricto invalidación -&gt; dispatch), EC-01 (idempotencia),
 * EC-02 (sin callees -&gt; sin dispatch), ES-04 (fail-closed en fallo de persistencia).
 */
@ExtendWith(MockitoExtension.class)
class TerminateSsoSessionWorkflowTest {

    private static final Instant NOW = Instant.parse("2026-01-15T10:00:00Z");
    private static final String TENANT = "tenant-a";
    private static final String INITIATOR = "app-a";
    private static final SsoSessionId SESSION_ID = SsoSessionId.of("opaque-session-id-123");
    private static final String HOLDER_HASH = "holder-hash-abc123";

    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private BackchannelLogoutUriPort backchannelLogoutUriPort;
    @Mock private BackChannelLogoutNotifierPort notifierPort;
    @Mock private SsoAuditPort auditPort;
    @Mock private BackendConfig backendConfig;

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    // Executor síncrono: ejecuta el Runnable en el mismo hilo, sin async real,
    // para que las aserciones de orden/interacción sean deterministas en el test.
    private final Executor syncExecutor = Runnable::run;

    private TerminateSsoSessionWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new TerminateSsoSessionWorkflow(
                sessionRepositoryPort,
                backchannelLogoutUriPort,
                notifierPort,
                auditPort,
                backendConfig,
                clock,
                syncExecutor
        );
    }

    private TerminateSsoSessionCommand command() {
        return new TerminateSsoSessionCommand(TENANT, SESSION_ID, INITIATOR, "corr-123", HOLDER_HASH);
    }

    // ─── AD-3: invalidación local ANTES de cualquier dispatch ─────────────────

    @Test
    void invalidatesBeforeNotifying() {
        when(sessionRepositoryPort.terminateActive(SESSION_ID, TENANT)).thenReturn(1);
        when(sessionRepositoryPort.findClientsBySession(SESSION_ID, TENANT))
                .thenReturn(List.of(INITIATOR, "callee-b"));
        when(backendConfig.getUrl()).thenReturn("https://idp.tenant-a.example.com");
        when(backchannelLogoutUriPort.resolve(TENANT, "callee-b"))
                .thenReturn(Optional.of("https://callee-b.example.com/backchannel-logout"));
        when(notifierPort.notifyLogout(any(), any()))
                .thenReturn(new DeliveryOutcome.Delivered("callee-b"));

        workflow.execute(command());

        InOrder inOrder = inOrder(sessionRepositoryPort, notifierPort);
        inOrder.verify(sessionRepositoryPort).terminateActive(SESSION_ID, TENANT);
        inOrder.verify(notifierPort).notifyLogout(any(), any());
    }

    // ─── EC-01: sesión ya TERMINATED / ausente — idempotente, sin re-dispatch ─

    @Test
    void noopOnAlreadyTerminated() {
        when(sessionRepositoryPort.terminateActive(SESSION_ID, TENANT)).thenReturn(0);

        workflow.execute(command());

        verify(sessionRepositoryPort, never()).findClientsBySession(any(), anyString());
        verify(notifierPort, never()).notifyLogout(any(), any());
        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED
                        && "noop".equals(event.getOutcome())));
    }

    // ─── EC-02: único aplicativo vivo = iniciador — sin callees, sin dispatch ─

    @Test
    void noDispatchWhenNoCallees() {
        when(sessionRepositoryPort.terminateActive(SESSION_ID, TENANT)).thenReturn(1);
        when(sessionRepositoryPort.findClientsBySession(SESSION_ID, TENANT))
                .thenReturn(List.of(INITIATOR));
        when(backendConfig.getUrl()).thenReturn("https://idp.tenant-a.example.com");

        workflow.execute(command());

        verify(backchannelLogoutUriPort, never()).resolve(any(), any());
        verify(notifierPort, never()).notifyLogout(any(), any());
        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED
                        && "success".equals(event.getOutcome())
                        && HOLDER_HASH.equals(event.getHolderHash())));
    }

    // ─── ES-04: fallo al persistir la invalidación — fail-closed, sin dispatch ─

    @Test
    void failClosedOnStoreError() {
        when(sessionRepositoryPort.terminateActive(SESSION_ID, TENANT))
                .thenThrow(new RuntimeException("DB timeout"));

        workflow.execute(command());

        verify(sessionRepositoryPort, never()).findClientsBySession(any(), anyString());
        verify(notifierPort, never()).notifyLogout(any(), any());
        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_LOGOUT_STORE_ERROR
                        && "error".equals(event.getOutcome())));
    }

    // ─── AC-04: callee sin backchannel_logout_uri — skip, no dispatch ─────────

    @Test
    void skipsCalleeWithoutBackchannelUri() {
        when(sessionRepositoryPort.terminateActive(SESSION_ID, TENANT)).thenReturn(1);
        when(sessionRepositoryPort.findClientsBySession(SESSION_ID, TENANT))
                .thenReturn(List.of(INITIATOR, "callee-c"));
        when(backendConfig.getUrl()).thenReturn("https://idp.tenant-a.example.com");
        when(backchannelLogoutUriPort.resolve(TENANT, "callee-c")).thenReturn(Optional.empty());

        workflow.execute(command());

        verify(notifierPort, never()).notifyLogout(any(), any());
        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.BACKCHANNEL_SKIPPED
                        && "callee-c".equals(event.getClientId())
                        && "skipped".equals(event.getOutcome())
                        && "no_backchannel_uri".equals(event.getReason())));
    }
}
