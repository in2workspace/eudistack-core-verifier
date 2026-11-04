package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.LoginMethod;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.AuthenticationSnapshot;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionAuthentication;
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
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static es.in2.vcverifier.sso.SsoTestAuthentications.credential;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-149/W2 (review): cubre {@code attachCredentialSnapshot} — el cifrado de las claims de la
 * credencial verificada antes de persistir la sesión SSO, y su contrato fail-closed (ES-02):
 * sin un snapshot cifrado no hay sesión ni cookie, exactamente igual que un fallo de persistencia.
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
    void execute_withoutAuthentication_failsClosed_noSessionNoCookie() {
        // W2 (review): no production caller ever reaches here without a verified credential —
        // treat its absence as an anomaly (same as a persistence failure), not a legitimate
        // "session without SSO reuse support" flow.
        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-1", null);

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNull(result, "Missing credential snapshot must fail closed: no session, no cookie");
        verify(credentialCipherPort, never()).encrypt(anyString(), anyString(), anyString());
        verify(sessionRepositoryPort, never()).save(any());

        ArgumentCaptor<SsoAuditEvent> eventCaptor = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(auditPort).publish(eventCaptor.capture());
        assertEquals(SsoAuditEvent.EventType.SSO_PERSIST_ERROR, eventCaptor.getValue().getEventType());
        assertEquals(HASHED_SUB, eventCaptor.getValue().getHolderHash());
    }

    @Test
    void execute_credentialJsonPresent_encryptsAndAttachesSnapshotBeforeSaving() {
        String credentialJson = "{\"vc\":\"claims\"}";
        byte[] ciphertext = "ciphertext-bytes".getBytes(StandardCharsets.UTF_8);
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString())).thenReturn(ciphertext);

        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-2", credential(credentialJson));

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNotNull(result);

        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertArrayEquals(ciphertext, sessionCaptor.getValue().getCredentialSnapshotCiphertext());
    }

    @Test
    void execute_certificateLogin_snapshotsItsTypedAuthenticationAndRecordsItsMethodLevelAndEnd() {
        Instant notAfter = Instant.parse("2028-05-01T00:00:00Z");
        CertificateAuthentication certificate = new CertificateAuthentication("b2f1c3",
                new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ", "NAME", null, "ES", "12345678Z"),
                "CN=AC FNMT Usuarios", "ab12", notAfter, AssuranceLevel.HIGH, List.of("hwk"),
                Instant.parse("2026-11-04T10:00:00Z"));
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString())).thenReturn(new byte[]{1});

        workflow.execute(new SsoSessionCommand(TENANT, SUB, "client-a", "corr-4", certificate));

        ArgumentCaptor<String> snapshot = ArgumentCaptor.forClass(String.class);
        verify(credentialCipherPort).encrypt(anyString(), anyString(), snapshot.capture());
        assertEquals(Optional.of(certificate), AuthenticationSnapshot.read(snapshot.getValue(), Instant.now()));
        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertEquals(new SsoSessionAuthentication(LoginMethod.X509, AssuranceLevel.HIGH, List.of("hwk"), notAfter),
                sessionCaptor.getValue().getAuthentication());
    }

    @Test
    void execute_walletLogin_recordsAWalletSession() {
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString())).thenReturn(new byte[]{1});

        workflow.execute(new SsoSessionCommand(TENANT, SUB, "client-a", "corr-5", credential("{\"vc\":\"claims\"}")));

        ArgumentCaptor<SsoSession> sessionCaptor = ArgumentCaptor.forClass(SsoSession.class);
        verify(sessionRepositoryPort).save(sessionCaptor.capture());
        assertEquals(new SsoSessionAuthentication(LoginMethod.WALLET, null, List.of("pop"), null),
                sessionCaptor.getValue().getAuthentication());
    }

    @Test
    void execute_encryptionThrows_failsClosed_noSessionNoCookie() {
        // W2 (review): a cipher failure must be as fail-closed as a DB persistence failure —
        // never persist a session + issue a cookie the Holder believes enables SSO when the
        // next silent reuse attempt is guaranteed to miss on CREDENTIAL_SNAPSHOT_MISSING.
        when(credentialCipherPort.encrypt(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("boom"));

        SsoSessionCommand command = new SsoSessionCommand(TENANT, SUB, "client-a", "corr-3", credential("{\"vc\":\"claims\"}"));

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor result = workflow.execute(command);

        assertNull(result, "A credential-snapshot encryption failure must fail closed, not establish a session");
        verify(sessionRepositoryPort, never()).save(any());

        ArgumentCaptor<SsoAuditEvent> eventCaptor = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(auditPort).publish(eventCaptor.capture());
        assertEquals(SsoAuditEvent.EventType.SSO_PERSIST_ERROR, eventCaptor.getValue().getEventType());
    }
}
