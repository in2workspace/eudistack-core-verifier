package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstablishSsoSessionWorkflow_ConfigAbsentTest {

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private SsoAuditPort auditPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    @DisplayName("Config ausente: fail-closed como legacy, sin sesión ni 500 (ES-01)")
    void execute_whenConfigAbsent_failsClosedAsLegacy() {

        var command = new SsoSessionCommand(
                "unknown-tenant",
                "holder-sub",
                "some-client",
                "corr-config-absent"
        );

        when(tenantSsoConfigPort.getByTenant("unknown-tenant"))
                .thenReturn(Optional.empty());

        assertThrows(
                SsoConfigInconsistentException.class,
                () -> workflow.execute(command)
        );

        verifyNoInteractions(sessionRepositoryPort);

        verify(tenantSsoConfigPort, times(1)).getByTenant("unknown-tenant");
        verify(tenantSsoConfigPort, never()).resolveTtl(anyString());
        verify(hashingService, never()).sha256(any());

        verify(auditPort, times(1)).publish(ArgumentMatchers.argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT
                        && "unknown-tenant".equals(e.getTenant())));
    }
}
