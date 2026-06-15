package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * ES-02
 *
 * Caso:
 * - fallo de persistencia (DB down o circuit breaker abierto)
 *
 * Esperado:
 * - NO cookie emitida
 * - evento sso_persist_error
 * - fallo controlado (sin propagación indefinida)
 */
@SpringBootTest
@ActiveProfiles("test")
class EstablishSsoSessionPersistenceFailureIT {

    @Autowired
    private EstablishSsoSessionWorkflow workflow;

    @MockitoBean
    private SsoSessionRepositoryPort repository;

    @MockitoBean
    private SsoAuditPort auditPort;

    @Test
    void shouldFailClosed_whenPersistenceFails_andEmitPersistErrorEvent() {

        // GIVEN
        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        // Simulamos fallo persistencia (DB caída / circuito abierto)
        doThrow(new RuntimeException("DB unavailable"))
                .when(repository).supersedeActive(any(), any());

        doThrow(new RuntimeException("DB unavailable"))
                .when(repository).save(any());

        // WHEN
        Exception exception = assertThrows(RuntimeException.class, () -> {
            workflow.execute(command);
        });

        // THEN
        assertNotNull(exception);

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR &&
                        event.getTenant().equals("tenant-a")
        ));

        // CRÍTICO: no se puede persistir sesión → NO debería haber éxito silencioso
        verify(repository, atLeastOnce()).supersedeActive("tenant-a", "2c0a...");

        verify(repository, atLeastOnce()).save(any());

        // opcional: asegurar que no se emitió evento de éxito
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED
        ));
    }
}

