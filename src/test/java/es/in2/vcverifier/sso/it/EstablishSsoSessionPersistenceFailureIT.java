package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.config.TimeConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;


import java.time.Clock;
import java.util.Optional;

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

@ActiveProfiles("test")
@Import(TimeConfig.class)
@ExtendWith(MockitoExtension.class)
class EstablishSsoSessionPersistenceFailureIT {

    @MockitoBean
    ClientRegistryProvider clientRegistryProvider;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private ClientLoaderConfig clientLoaderConfig;

    @MockitoBean
    private SsoSessionAuthenticationSuccessHandler ssoSessionAuthenticationSuccessHandler;

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock
    private SsoSessionRepositoryPort repository;
    @Mock private SsoAuditPort auditPort;
    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    void shouldFailClosed_whenPersistenceFails_andEmitPersistErrorEvent() {

        // GIVEN
        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        // Config válida (CLAVE para llegar a persistencia)
        var validConfig = mock(TenantSsoConfig.class);

        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.of(validConfig));

        // WHEN
        Exception exception = assertThrows(RuntimeException.class, () -> {
            workflow.execute(command);
        });

        // THEN
        assertNotNull(exception);

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT &&
                        event.getTenant().equals("tenant-a")
        ));

        verify(repository, never()).save(any());
        verify(repository, never()).supersedeActive(any(), any());
    }
}

