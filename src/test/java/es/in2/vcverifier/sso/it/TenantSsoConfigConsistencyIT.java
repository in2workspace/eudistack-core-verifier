package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

/**
 * Caso:
 * Verifica que, cuando la configuración SSO está ausente o deshabilitada, el workflow lanza una excepción
 * y publica un evento de auditoría de configuración inconsistente sin crear sesión ni persistir datos.
 *
 *
 * Esperado:
 * - Se lanza SsoConfigInconsistentException
 * - Se emite evento SSO_CONFIG_INCONSISTENT
 * - NO se crea ni persiste sesión SSO
 * - NO se ejecuta persistencia en el repositorio de sesiones
 */

@ExtendWith(MockitoExtension.class)
class TenantSsoConfigConsistencyIT {

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private SsoAuditPort auditPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    void shouldPublishAuditAndThrow_whenConfigIsMissing() {

        // GIVEN
        var command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.empty());

        // WHEN
        assertThrows(
                EstablishSsoSessionWorkflow.SsoConfigInconsistentException.class,
                () -> workflow.execute(command)
        );

        // THEN - audit MUST be called
        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        "tenant-a".equals(event.getTenant())
        ));

        verifyNoInteractions(sessionRepositoryPort);
    }

    @Test
    void shouldPublishAuditAndThrow_whenSsoDisabled() {

        var command = new SsoSessionCommand(
                "tenant-b",
                "holder-xyz",
                "client-test",
                "corr-456"
        );

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(Boolean.FALSE);

        when(tenantSsoConfigPort.getByTenant("tenant-b"))
                .thenReturn(Optional.of(config));

        assertThrows(
                EstablishSsoSessionWorkflow.SsoConfigInconsistentException.class,
                () -> workflow.execute(command)
        );

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        "tenant-b".equals(event.getTenant())
        ));

        verifyNoInteractions(sessionRepositoryPort);
    }
}