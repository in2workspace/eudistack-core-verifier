package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-149: cubre {@code attachCredentialSnapshot} — el cifrado (fail-open) de las claims de la
 * credencial verificada antes de persistir la sesión SSO.
 */
class EstablishSsoSessionWorkflow_CredentialSnapshotTest {

    private static final String TENANT = "tenant-a";
    private static final String SUB = "did:key:z6MkSubject";
    private static final String HASHED_SUB = "hashed-sub";

    private TenantSsoConfigPort configPort;
    private SsoSessionRepositoryPort sessionRepositoryPort;
    private SsoAuditPort auditPort;
    private SsoMetricsPort metricsPort;
    private HashingService hashingService;
    private SsoCredentialCipherPort credentialCipherPort;
    private EstablishSsoSessionWorkflow workflow;

    @BeforeEach
    void setUp() {
        configPort = mock(TenantSsoConfigPort.class);
        sessionRepositoryPort = mock(SsoSessionRepositoryPort.class);
        auditPort = mock(SsoAuditPort.class);
        metricsPort = mock(SsoMetricsPort.class);
        hashingService = mock(HashingService.class);
        credentialCipherPort = mock(SsoCredentialCipherPort.class);

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "example.com", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofMinutes(30)),
                List.of());

        when(configPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(configPort.resolveTtl(TENANT)).thenReturn(SsoSessionTtl.systemDefault());
        when(hashingService.sha256(SUB)).thenReturn(HASHED_SUB);

        workflow = new EstablishSsoSessionWorkflow(
                configPort, sessionRepositoryPort, auditPort, metricsPort,
                hashingService, Clock.systemUTC(), credentialCipherPort);
    }

    @Test
    void execute_blankCredentialJson_skipsEncryptionAndSavesSessionWithoutSnapshot() {
        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-1", "   ");

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNotNull(result);
        verify(credentialCipherPort, never()).encrypt(anyString(), anyString(), anyString());

        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertNull(sessionCaptor.getValue().getCredentialSnapshotCiphertext());
    }

    @Test
    void execute_credentialJsonPresent_encryptsAndAttachesSnapshotBeforeSaving() {
        String credentialJson = "{\"vc\":\"claims\"}";
        byte[] ciphertext = "ciphertext-bytes".getBytes(StandardCharsets.UTF_8);
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString())).thenReturn(ciphertext);

        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-2", credentialJson);

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNotNull(result);

        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertArrayEquals(ciphertext, sessionCaptor.getValue().getCredentialSnapshotCiphertext());
    }

    @Test
    void execute_encryptionThrows_failsOpenAndSavesSessionWithoutSnapshot() {
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("boom"));

        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-3", "{\"vc\":\"claims\"}");

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNotNull(result, "A credential-snapshot encryption failure must not block session establishment");

        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertNull(sessionCaptor.getValue().getCredentialSnapshotCiphertext());
    }
}
