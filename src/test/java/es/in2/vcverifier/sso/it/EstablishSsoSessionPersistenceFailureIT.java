package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EstablishSsoSessionPersistenceFailureIT {

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private SsoSessionRepositoryPort repository;
    @Mock private SsoAuditPort            auditPort;
    @Mock private TenantSsoConfigPort     tenantSsoConfigPort;
    @Mock private HashingService          hashingService;
    @Mock private Clock                   clock;

    @Test
    void shouldFailClosed_whenPersistenceFails_andEmitPersistErrorEvent() {

        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(Boolean.TRUE);

        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.of(config));

        // resolveTtl añadido en US-04: debe stubbearse para que ttl.absolute() no lance NPE
        when(tenantSsoConfigPort.resolveTtl("tenant-a"))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30)));

        when(hashingService.sha256(any())).thenReturn("hash-123");

        // supersedeActive completa sin error; save es el punto de fallo
        doNothing().when(repository).supersedeActive(any(), any());
        doThrow(new RuntimeException("DB down")).when(repository).save(any());

        // WHEN
        var result = assertDoesNotThrow(() -> workflow.execute(command));

        // THEN
        assertNull(result, "No debe emitirse cookie en fallo de persistencia.");

        verify(repository).supersedeActive(eq("tenant-a"), any());
        verify(repository).save(any());
        verifyNoMoreInteractions(repository);

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR &&
                        event.getTenant().equals("tenant-a")
        ));
    }
}
