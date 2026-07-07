package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.exception.SsoDisabledForTenantException;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
class EstablishSsoSessionWorkflow_SsoDisabledTest {

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private SsoAuditPort auditPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    @DisplayName("SSO deshabilitado (legacy): no persiste sesión ni genera cookie (AC-01, NFR-S-553-02)")
    void execute_whenSsoDisabled_doesNotPersistSession() {

        var command = new SsoSessionCommand(
                "legacy-tenant",
                "holder-sub",
                "legacy-client",
                "corr-sso-disabled"
        );

        TenantSsoConfig config = org.mockito.Mockito.mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(Boolean.FALSE);
        when(tenantSsoConfigPort.getByTenant("legacy-tenant"))
                .thenReturn(Optional.of(config));

        // Legacy intencional → excepción benigna (no SsoConfigInconsistentException).
        assertThrows(
                SsoDisabledForTenantException.class,
                () -> workflow.execute(command)
        );

        verifyNoInteractions(sessionRepositoryPort);

        verify(tenantSsoConfigPort, times(1)).getByTenant("legacy-tenant");
        verify(tenantSsoConfigPort, never()).resolveTtl(anyString());
        verify(hashingService, never()).sha256(any());

        verifyNoInteractions(auditPort);
    }
}
