package es.in2.vcverifier.sso.application.workflow;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionState;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-149: cubre el snapshot de credencial cifrado que sustituye la antigua caché en memoria —
 * en particular {@code decryptCredentialSnapshot} (fail-closed a LOGIN_REQUIRED en cualquier
 * variante de fallo) y el paso de {@code max_age} (AuthorizationContext) a {@code TenantSsoPolicy}.
 */
class ReuseSsoSessionWorkflowImpl_CredentialSnapshotTest {

    private static final String TENANT = "tenant-a";
    private static final String CLIENT_ID = "client-a";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String ISSUER = "https://tenant-a.verifier.example.com/verifier";
    private static final Instant NOW = Instant.parse("2026-09-08T10:00:00Z");

    private TenantSsoConfigPort configPort;
    private SsoSessionRepositoryPort sessionRepository;
    private SsoAuditPort auditPort;
    private SsoMetricsPort metricsPort;
    private RegisteredClientRepository registeredClientRepository;
    private AuthorizationResponseProcessorService authorizationResponseProcessorService;
    private SsoCredentialCipherPort credentialCipherPort;
    private ReuseSsoSessionWorkflowImpl workflow;

    @BeforeEach
    void setUp() {
        configPort = mock(TenantSsoConfigPort.class);
        sessionRepository = mock(SsoSessionRepositoryPort.class);
        auditPort = mock(SsoAuditPort.class);
        metricsPort = mock(SsoMetricsPort.class);
        registeredClientRepository = mock(RegisteredClientRepository.class);
        authorizationResponseProcessorService = mock(AuthorizationResponseProcessorService.class);
        credentialCipherPort = mock(SsoCredentialCipherPort.class);

        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

        workflow = new ReuseSsoSessionWorkflowImpl(
                configPort, sessionRepository, clock, auditPort, metricsPort,
                registeredClientRepository, authorizationResponseProcessorService,
                credentialCipherPort, new ObjectMapper());

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "example.com", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofMinutes(30)),
                List.of());
        when(configPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(configPort.resolveTtl(TENANT)).thenReturn(SsoSessionTtl.systemDefault());

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(CLIENT_ID)
                .clientName("Test Client")
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri(REDIRECT_URI)
                .build();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);
    }

    private SsoSession activeSession(String cookieValue, byte[] credentialSnapshotCiphertext) {
        SsoSession session = SsoSession.reconstitute(
                SsoSessionId.of(cookieValue),
                TENANT,
                "holder-hash",
                NOW.minusSeconds(60),
                NOW.plusSeconds(3600),
                NOW,
                SsoSessionState.ACTIVE);
        session.attachCredentialSnapshot(credentialSnapshotCiphertext);
        return session;
    }

    private AuthorizationContext ctxAllowingReuse() {
        return AuthorizationContext.builder()
                .redirectUri(REDIRECT_URI)
                .scope("openid learcredential")
                .state("state-1")
                .issuer(ISSUER)
                .build();
    }

    @Test
    void reuse_ctxNullAndCatalogRejectsClient_returnsInteractionRequired() {
        String cookieValue = "session-cookie-value";
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, null)));
        when(configPort.resolveEligibleClients(TENANT)).thenReturn(TenantSsoCatalog.empty());

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, null, CLIENT_ID, "corr-1");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.INTERACTION_REQUIRED, result.status());
        verify(credentialCipherPort, never()).decrypt(anyString(), anyString(), any());
    }

    @Test
    void reuse_missingCredentialSnapshot_failsClosedToLoginRequired() {
        String cookieValue = "session-cookie-value";
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, null)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-2");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());
        verify(credentialCipherPort, never()).decrypt(anyString(), anyString(), any());
    }

    @Test
    void reuse_decryptReturnsEmpty_failsClosedToLoginRequired() {
        String cookieValue = "session-cookie-value";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, ciphertext)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext)).thenReturn(Optional.empty());

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-3");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());
    }

    @Test
    void reuse_decryptedJsonMalformed_shortSessionId_failsClosedToLoginRequired() {
        // 8 chars: exercises the "value not truncated" branch of the logged session-id prefix.
        String cookieValue = "shortid1";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, ciphertext)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext)).thenReturn(Optional.of("{not-json"));

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-4");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());
    }

    @Test
    void reuse_decryptedJsonMalformed_longSessionId_failsClosedToLoginRequired() {
        // >8 chars: exercises the substring/truncation branch of the logged session-id prefix.
        String cookieValue = "a-much-longer-session-cookie-value";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, ciphertext)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext)).thenReturn(Optional.of("{not-json"));

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-5");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());
    }

    @Test
    void reuse_fullHappyPath_decryptsSnapshotAndReturnsAllowedRedirect() {
        String cookieValue = "session-cookie-value";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, ciphertext)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext))
                .thenReturn(Optional.of("{\"vc\":\"claims\"}"));
        when(authorizationResponseProcessorService.issueCodeForReusedSession(
                eq(CLIENT_ID), eq(REDIRECT_URI), any(), eq("state-1"), any(), any(), any(), any(), any(), any()))
                .thenReturn(REDIRECT_URI + "?code=abc&state=state-1");

        ReuseSsoSessionWorkflow.Result result =
                workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-6");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.ALLOWED, result.status());
        assertNotNull(result.redirectUrl());
        // EUD-300: the code carries the session's original authentication time (auth_time),
        // and the response the /authorize issuer (RFC 9207 iss).
        verify(authorizationResponseProcessorService).issueCodeForReusedSession(
                eq(CLIENT_ID), eq(REDIRECT_URI), any(), eq("state-1"), any(), any(), any(), any(),
                eq(NOW.minusSeconds(60)), eq(ISSUER));
        verify(metricsPort).recordReuse(TENANT, CLIENT_ID);
        verify(metricsPort).recordOid4vpAvoided(TENANT);
    }

    @Test
    void reuse_touchFails_logsClassNamesOnlyAtWarnAndThrowableAtDebug() throws InterruptedException {
        // Given: a session last used long enough ago to be touched, and a touch failure whose
        // driver detail carries the full session id (the cookie value)
        String cookieValue = "full-session-id-that-is-the-cookie";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        SsoSession session = SsoSession.reconstitute(SsoSessionId.of(cookieValue), TENANT, "holder-hash",
                NOW.minusSeconds(600), NOW.plusSeconds(3600), NOW.minusSeconds(300), SsoSessionState.ACTIVE);
        session.attachCredentialSnapshot(ciphertext);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT)).thenReturn(Optional.of(session));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext)).thenReturn(Optional.of("{\"vc\":\"claims\"}"));
        when(authorizationResponseProcessorService.issueCodeForReusedSession(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(REDIRECT_URI + "?code=abc&state=state-1");
        doThrow(new IllegalStateException("update failed", new SQLException("Key (id)=(" + cookieValue + ")")))
                .when(sessionRepository).updateLastUsedAt(any(), any(), any());

        Logger logger = (Logger) LoggerFactory.getLogger(ReuseSsoSessionWorkflowImpl.class);
        Level previousLevel = logger.getLevel();
        CountDownLatch debugLogged = new CountDownLatch(1);
        ListAppender<ILoggingEvent> appender = new ListAppender<>() {
            @Override
            protected void append(ILoggingEvent event) {
                super.append(event);
                if (event.getLevel() == Level.DEBUG && event.getFormattedMessage().startsWith("sso_touch_failed")) {
                    debugLogged.countDown();
                }
            }
        };
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            // When: the touch runs asynchronously after the reuse decision
            workflow.reuse(TENANT, cookieValue, ctxAllowingReuse(), CLIENT_ID, "corr-8");
            assertTrue(debugLogged.await(5, TimeUnit.SECONDS), "sso_touch_failed was never logged");
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
        }

        // Then
        ILoggingEvent warn = appender.list.stream()
                .filter(e -> e.getLevel() == Level.WARN && e.getFormattedMessage().startsWith("sso_touch_failed"))
                .findFirst().orElseThrow();
        assertEquals("sso_touch_failed session=full-ses tenant=" + TENANT
                + " error=IllegalStateException rootCause=SQLException", warn.getFormattedMessage());
        assertNull(warn.getThrowableProxy());
        assertTrue(appender.list.stream().anyMatch(e -> e.getLevel() == Level.DEBUG
                && e.getFormattedMessage().startsWith("sso_touch_failed") && e.getThrowableProxy() != null));
    }

    @Test
    void reuse_redirectUriNotRegisteredForClient_failsClosedToLoginRequiredWithoutIssuingCode() {
        // Defense in depth: the converter validates redirect_uri before calling reuse, but the
        // workflow must never issue a code for a URI not registered to this client either.
        String cookieValue = "session-cookie-value";
        byte[] ciphertext = "ciphertext".getBytes(StandardCharsets.UTF_8);
        when(sessionRepository.findActiveById(SsoSessionId.of(cookieValue), TENANT))
                .thenReturn(Optional.of(activeSession(cookieValue, ciphertext)));
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(List.of(es.in2.vcverifier.sso.domain.model.SsoEligibleClient.of(CLIENT_ID))));
        when(credentialCipherPort.decrypt(TENANT, cookieValue, ciphertext))
                .thenReturn(Optional.of("{\"vc\":\"claims\"}"));
        AuthorizationContext ctx = ctxAllowingReuse().toBuilder()
                .redirectUri("https://client.example.com/not-the-registered-path")
                .build();

        ReuseSsoSessionWorkflow.Result result = workflow.reuse(TENANT, cookieValue, ctx, CLIENT_ID, "corr-7");

        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());
        verify(authorizationResponseProcessorService, never()).issueCodeForReusedSession(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
        verify(auditPort).publish(org.mockito.ArgumentMatchers.argThat(e ->
                "REDIRECT_URI_MISMATCH".equals(e.getOutcome())));
    }
}
