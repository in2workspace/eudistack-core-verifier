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
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ActiveProfiles("test")
@Import(TimeConfig.class)
@ExtendWith(MockitoExtension.class)
class EstablishSsoSessionPersistenceFailureIT {

    @MockitoBean ClientRegistryProvider clientRegistryProvider;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean ClientLoaderConfig clientLoaderConfig;
    @MockitoBean SsoSessionAuthenticationSuccessHandler handler;

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private SsoSessionRepositoryPort repository;
    @Mock private SsoAuditPort auditPort;
    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    void shouldFailClosed_whenPersistenceFails_andEmitPersistErrorEvent() {

        SsoSessionCommand command = new SsoSessionCommand(
                "tenant-a",
                "holder-xyz",
                "client-test",
                "corr-123"
        );

        // CONFIG MOCK CORRECTO
        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(true);

        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.of(config));

        when(hashingService.sha256(any())).thenReturn("hash-123");

        // fallo SOLO en save (no en supersedeActive)
        doNothing().when(repository).supersedeActive(any(), any());
        doThrow(new RuntimeException("DB down"))
                .when(repository).save(any());

        // WHEN
        var result = assertDoesNotThrow(() -> workflow.execute(command));


        // THEN
        assertNull(result, "No debe emitirse cookie en fallo de persistencia");

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR &&
                        event.getTenant().equals("tenant-a")
        ));

        verify(repository).supersedeActive(eq("tenant-a"), any());

        verifyNoMoreInteractions(repository);

        verify(auditPort).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR &&
                        e.getTenant().equals("tenant-a")
        ));
    }
}