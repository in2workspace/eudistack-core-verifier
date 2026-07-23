package es.in2.vcverifier.sso.it;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.Constants;
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
 * IT — US-06 EC-03: un callee que falla en el primer intento (5xx transitorio) pero responde
 * 200 OK dentro de los reintentos configurados ({@code BackChannelLogoutDispatcher}: 3 intentos,
 * backoff exponencial 500ms base + jitter, todo por debajo del timeout de 5s) debe recibir
 * {@code backchannel_delivered} SOLO tras el 200 OK final, y el circuit breaker per
 * {@code client_id} no debe abrirse (el umbral son 5 fallos consecutivos; aquí solo hay 1).
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class BackChannelLogoutRetryIT {

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

    private static HttpServer calleeServer;
    private static AtomicInteger calleeAttempts;
    private static String calleeBackchannelUri;

    @BeforeAll
    static void startFlakyCalleeServer() throws IOException {
        calleeAttempts = new AtomicInteger(0);
        calleeServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        calleeServer.createContext("/backchannel-logout", BackChannelLogoutRetryIT::handleFlakyRequest);
        calleeServer.start();
        calleeBackchannelUri = "http://localhost:" + calleeServer.getAddress().getPort() + "/backchannel-logout";
    }

    @AfterAll
    static void stopCalleeServer() {
        calleeServer.stop(0);
    }

    /** Falla (500) en el primer intento, responde 200 OK a partir del segundo. */
    private static void handleFlakyRequest(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        int attempt = calleeAttempts.incrementAndGet();
        if (attempt == 1) {
            exchange.sendResponseHeaders(500, -1);
        } else {
            exchange.sendResponseHeaders(200, -1);
        }
        exchange.close();
    }

    @BeforeEach
    void cleanState() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");
        calleeAttempts.set(0);

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(Set.of()));
    }

    // =========================================================
    // EC-03: 1 fallo transitorio + éxito en el reintento — backchannel_delivered, breaker cerrado.
    // =========================================================
    @Test
    void singleLogout_deliversAfterOneTransientFailure_andKeepsCircuitClosed() throws Exception {
        String initiatorClientId = "initiator-ec03";
        String calleeClientId = "callee-ec03-flaky";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, calleeClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(calleeClientId, null, calleeBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ec03");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        // backoff base 500ms + jitter tras el 1er fallo: dar margen amplio (5s) al reintento.
        verify(auditPort, timeout(5000)).publish(argThatEventType(
                es.in2.vcverifier.sso.domain.model.SsoAuditEvent.EventType.BACKCHANNEL_DELIVERED,
                calleeClientId));

        assertThat(calleeAttempts.get())
                .as("debe haber exactamente 1 fallo + 1 éxito (2 intentos totales)")
                .isEqualTo(2);

        // El circuit breaker per client_id abre a partir de 5 fallos consecutivos; aquí solo
        // hubo 1 fallo antes del éxito, así que NUNCA debe reportarse backchannel_failed.
        verify(auditPort, org.mockito.Mockito.never()).publish(argThatEventType(
                es.in2.vcverifier.sso.domain.model.SsoAuditEvent.EventType.BACKCHANNEL_FAILED,
                calleeClientId));
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

    private void insertSessionClient(String sessionId, String clientId) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session_client (session_id, tenant, client_id, first_seen_at, last_used_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                sessionId, TENANT, clientId, now, now);
    }

    private es.in2.vcverifier.sso.domain.model.SsoAuditEvent argThatEventType(
            es.in2.vcverifier.sso.domain.model.SsoAuditEvent.EventType type, String clientId) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type && clientId.equals(event.getClientId()));
    }
}
