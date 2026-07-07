package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.exception.SsoDisabledForTenantException;
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
 * Caso (US-08 B2 — semántica de eventos del guard de establecimiento):
 * El guard distingue "config ausente/incoherente inesperada" de "tenant legacy intencional".
 *
 * Esperado:
 * - Config AUSENTE (sin entrada) → lanza SsoConfigInconsistentException + emite SSO_CONFIG_INCONSISTENT.
 * - SSO DESHABILITADO (config coherente, sso.enabled=false) → lanza la excepción benigna
 *   SsoDisabledForTenantException y NO emite ningún evento de auditoría (ES-01, NFR-S-553-01).
 * - En ambos casos NO se crea ni persiste sesión SSO.
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

        // WHEN — Config ausente = recurso inesperado → SsoConfigInconsistentException + evento.
        assertThrows(
                SsoConfigInconsistentException.class,
                () -> workflow.execute(command)
        );

        // THEN - audit MUST be called
        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        "tenant-a".equals(event.getTenant())));

        verifyNoInteractions(sessionRepositoryPort);
    }

    @Test
    void shouldThrowBenignAndNotAudit_whenSsoDisabled() {

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
                SsoDisabledForTenantException.class,
                () -> workflow.execute(command)
        );

        verifyNoInteractions(auditPort);
        verifyNoInteractions(sessionRepositoryPort);
    }
}
