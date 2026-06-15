package es.in2.vcverifier.sso.it;


import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * ES-03
 *
 * Caso:
 * - Config SSO inexistente o inconsistente en establish-time
 *
 * Resultado esperado:
 * - fallback legacy (NO sesión SSO creada)
 * - evento sso_config_inconsistent emitido
 * - flujo continúa sin bloquear sistema
 */
@SpringBootTest
@ActiveProfiles("test")
class TenantSsoConfigConsistencyIT {

    @Autowired
    private EstablishSsoSessionWorkflow workflow;

    @MockitoBean
    private TenantSsoConfigPort tenantSsoConfigPort;

    @MockitoBean
    private SsoAuditPort auditPort;

    @Test
    void shouldFallbackToLegacy_whenConfigIsMissing_andEmitConfigInconsistentEvent() {

        // GIVEN
        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        // Simulamos config AUSENTE
        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.empty());

        // WHEN
        Exception ex = assertThrows(RuntimeException.class, () -> {
            workflow.execute(command);
        });

        // THEN: error controlado
        assertNotNull(ex);

        // AUDITORÍA obligatoria
        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        event.getTenant().equals("tenant-a")
        ));

        // FALLBACK LEGACY: NO debe intentar persistir sesión válida
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED
        ));
    }

    @Test
    void shouldFallbackToLegacy_whenSsoDisabled_andEmitConfigInconsistentEvent() {

        // GIVEN
        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-b",
                "holder-xyz",
                "client-test",
                "corr-456"
        );

        TenantSsoConfig disabledConfig = mock(TenantSsoConfig.class);
        when(disabledConfig.ssoEnabled()).thenReturn(false);

        when(tenantSsoConfigPort.getByTenant("tenant-b"))
                .thenReturn(Optional.of(disabledConfig));

        // WHEN
        Exception ex = assertThrows(RuntimeException.class, () -> {
            workflow.execute(command);
        });

        // THEN
        assertNotNull(ex);

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        event.getTenant().equals("tenant-b")
        ));

        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED
        ));
    }
}