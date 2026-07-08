package es.in2.vcverifier.sso.it;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.Constants;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 ES-02: un callee con fallo persistente (5xx en todos los intentos) agota los 3
 * reintentos de {@code BackChannelLogoutDispatcher} y emite {@code backchannel_failed} — sin
 * revertir la invalidación local (ya confirmada, AD-3) ni bloquear el dispatch a otros callees.
 * Tras 5 fallos consecutivos para el mismo {@code client_id}, el circuit breaker abre: los
 * dispatches siguientes se rechazan sin llegar a la red, con {@code outcome=circuit_open}.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class BackChannelLogoutFailureIT {

    private static final String TENANT = "tenant-a";
    private static final String POST_LOGOUT_REDIRECT_URI = "https://initiator.example.com/logged-out";

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private OAuth2AuthorizationService authorizationService;

    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    private static HttpServer failingServer;
    private static HttpServer okServer;
    private static AtomicInteger failingServerHits;
    private static String failingBackchannelUri;
    private static String okBackchannelUri;

    @BeforeAll
    static void startCalleeServers() throws IOException {
        failingServerHits = new AtomicInteger(0);

        failingServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        failingServer.createContext("/backchannel-logout", exchange -> {
            exchange.getRequestBody().readAllBytes();
            failingServerHits.incrementAndGet();
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        failingServer.start();
        failingBackchannelUri = "http://localhost:" + failingServer.getAddress().getPort() + "/backchannel-logout";

        okServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        okServer.createContext("/backchannel-logout", BackChannelLogoutFailureIT::handleOk);
        okServer.start();
        okBackchannelUri = "http://localhost:" + okServer.getAddress().getPort() + "/backchannel-logout";
    }

    private static void handleOk(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
    }

    @AfterAll
    static void stopCalleeServers() {
        failingServer.stop(0);
        okServer.stop(0);
    }

    @BeforeEach
    void cleanState() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");
        failingServerHits.set(0);

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(Set.of()));
    }

    // =========================================================
    // ES-02: fallo persistente en un callee — no revierte invalidación, no bloquea al otro callee.
    // =========================================================
    @Test
    void singleLogout_recordsFailure_withoutRevertingInvalidation_orBlockingOtherCallees() throws Exception {
        String initiatorClientId = "initiator-es02";
        String failingClientId = "callee-es02-failing";
        String okClientId = "callee-es02-ok";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, failingClientId);
        insertSessionClient(sessionId, okClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(failingClientId, null, failingBackchannelUri);
        registerClient(okClientId, null, okBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-es02");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        // AD-3: la invalidación local ya se confirmó ANTES del dispatch — un fallo de callee
        // no la revierte jamás.
        assertThat(sessionState(sessionId)).isEqualTo("TERMINATED");

        verify(auditPort, timeout(6000)).publish(argThatEventType(
                SsoAuditEvent.EventType.BACKCHANNEL_FAILED, failingClientId));
        verify(auditPort, timeout(6000)).publish(argThatEventType(
                SsoAuditEvent.EventType.BACKCHANNEL_DELIVERED, okClientId));

        assertThat(failingServerHits.get())
                .as("el dispatcher agota los 3 intentos configurados")
                .isEqualTo(3);
    }

    // =========================================================
    // ES-02: 5 fallos consecutivos al mismo client_id abren el circuit breaker.
    // =========================================================
    @Test
    void singleLogout_opensCircuitBreaker_after5ConsecutiveFailuresToSameClient() throws Exception {
        String failingClientId = "callee-es02-circuit";
        registerClient(failingClientId, null, failingBackchannelUri);

        for (int i = 0; i < 5; i++) {
            dispatchOnceToFailingCallee("initiator-circuit-" + i, failingClientId);
        }

        verify(auditPort, timeout(15000).times(5)).publish(argThatEventType(
                SsoAuditEvent.EventType.BACKCHANNEL_FAILED, failingClientId));

        int hitsBeforeSixthAttempt = failingServerHits.get();

        // 6º dispatch: el circuit breaker (5 fallos consecutivos → abierto 60s) debe rechazar
        // sin llegar a la red — cero hits adicionales al callee.
        dispatchOnceToFailingCallee("initiator-circuit-open", failingClientId);

        verify(auditPort, timeout(3000)).publish(argThatEventTypeAndOutcome(
                SsoAuditEvent.EventType.BACKCHANNEL_FAILED, failingClientId, "circuit_open"));

        assertThat(failingServerHits.get())
                .as("con el circuit breaker abierto, el 6º dispatch no debe llegar a la red")
                .isEqualTo(hitsBeforeSixthAttempt);
    }

    private void dispatchOnceToFailingCallee(String initiatorClientId, String failingClientId) throws Exception {
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, failingClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-" + initiatorClientId);

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private RegisteredClient registerClient(String clientId, String postLogoutRedirectUri, String backchannelLogoutUri) {
        var builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://" + clientId + ".example.com/callback")
                .scope(OidcScopes.OPENID);

        if (postLogoutRedirectUri != null) {
            builder.postLogoutRedirectUri(postLogoutRedirectUri);
        }
        if (backchannelLogoutUri != null) {
            builder.clientSettings(ClientSettings.builder()
                    .setting(Constants.CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI, backchannelLogoutUri)
                    .build());
        }
        RegisteredClient client = builder.build();
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(client);
        return client;
    }

    private String saveIdTokenAuthorization(RegisteredClient client, String subject) {
        String tokenValue = UUID.randomUUID().toString();
        Instant now = Instant.now();

        OidcIdToken idToken = OidcIdToken.withTokenValue(tokenValue)
                .subject(subject)
                .audience(List.of(client.getClientId()))
                .issuer("https://" + TENANT + ".example.com")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(subject)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(idToken)
                .build();

        authorizationService.save(authorization);
        return tokenValue;
    }

    private String insertActiveSession() {
        String id = UUID.randomUUID().toString();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, TENANT, "holder-" + id,
                now, now.plusHours(1), now);
        return id;
    }

    private String sessionState(String sessionId) {
        return jdbcTemplate.queryForObject(
                "SELECT state FROM sso_session WHERE id = ?", String.class, sessionId);
    }

    private void insertSessionClient(String sessionId, String clientId) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session_client (session_id, tenant, client_id, first_seen_at, last_used_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                sessionId, TENANT, clientId, now, now);
    }

    private SsoAuditEvent argThatEventType(SsoAuditEvent.EventType type, String clientId) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type && clientId.equals(event.getClientId()));
    }

    private SsoAuditEvent argThatEventTypeAndOutcome(SsoAuditEvent.EventType type, String clientId, String outcome) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type
                        && clientId.equals(event.getClientId())
                        && outcome.equals(event.getOutcome()));
    }
}
