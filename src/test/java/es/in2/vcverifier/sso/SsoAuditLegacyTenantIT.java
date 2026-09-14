package es.in2.vcverifier.sso;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.application.workflow.ReuseSsoSessionWorkflowImpl;
import es.in2.vcverifier.sso.domain.exception.SsoDisabledForTenantException;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Clock;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoAuditLegacyTenantIT {

    @InjectMocks
    private EstablishSsoSessionWorkflow establishWorkflow;

    @InjectMocks
    private ReuseSsoSessionWorkflowImpl reuseWorkflow;

    @Mock private TenantSsoConfigPort configPort;
    @Mock private SsoSessionRepositoryPort sessionRepository;
    @Mock private SsoAuditPort auditPort;
    @Mock private SsoMetricsPort metricsPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;
    @Mock private RegisteredClientRepository registeredClientRepository;

    @Test
    void establish_onLegacyTenant_emitsNoAuditNorMetrics() {
        TenantSsoConfig legacy = legacyConfig();
        when(configPort.getByTenant("legacy-tenant")).thenReturn(Optional.of(legacy));

        SsoSessionCommand command =
                new SsoSessionCommand("legacy-tenant", "holder-sub", "legacy-client", "corr-legacy");

        assertThrows(SsoDisabledForTenantException.class, () -> establishWorkflow.execute(command));

        verifyNoInteractions(auditPort);
        verifyNoInteractions(metricsPort);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    void reuse_onLegacyTenant_emitsNoAuditNorMetrics() {
        TenantSsoConfig legacy = legacyConfig();
        when(configPort.getByTenant("legacy-tenant")).thenReturn(Optional.of(legacy));

        ReuseSsoSessionWorkflow.Result result =
                reuseWorkflow.reuse("legacy-tenant", "cookie-value", null, "legacy-client");

        assertThat(result.status()).isEqualTo(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        verifyNoInteractions(auditPort);
        verifyNoInteractions(metricsPort);
    }

    private TenantSsoConfig legacyConfig() {
        TenantSsoConfig config = org.mockito.Mockito.mock(TenantSsoConfig.class);
        lenient().when(config.ssoEnabled()).thenReturn(Boolean.FALSE);
        return config;
    }
}
