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
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 Single Logout end-to-end sobre el endpoint real {@code POST /oidc/logout}
 * (OIDC RP-Initiated Logout 1.0 de Spring Authorization Server), con Postgres real
 * (Testcontainers) y un callee HTTP real (servidor JDK local, sin dependencias nuevas).
 * <p>
 * No autentica al principal en el request (sin login, sin HttpSession): esto hace que
 * {@code OidcLogoutAuthenticationToken.isPrincipalAuthenticated()} evalúe a {@code false}
 * (el converter usa un {@code AnonymousAuthenticationToken} por defecto), por lo que
 * {@code OidcLogoutAuthenticationProvider} omite la validación de {@code sub}/{@code sid}
 * frente a sesión HTTP — solo valida {@code id_token_hint} (resuelto vía
 * {@link OAuth2AuthorizationService#findByToken}, NO por firma JWT) y
 * {@code post_logout_redirect_uri} contra el {@link RegisteredClient}. Verificado contra
 * el bytecode real de Spring Authorization Server 1.5.6 (mismo rigor que Task 8).
 *
 * <p>Escenarios: AC-01 (happy path con callee notificado), EC-01 (doble logout idempotente,
 * sin re-dispatch), EC-02 (único aplicativo vivo = iniciador, sin callees).
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SingleLogoutIT {

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

    // Callee HTTP real (JDK, sin nueva dependencia) — captura la entrega del logout_token.
    private static HttpServer calleeServer;
    private static LinkedBlockingQueue<String> calleeRequestBodies;
    private static String calleeBackchannelUri;

    @BeforeAll
    static void startCalleeServer() throws IOException {
        calleeRequestBodies = new LinkedBlockingQueue<>();
        calleeServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        calleeServer.createContext("/backchannel-logout", SingleLogoutIT::handleBackchannelLogoutRequest);
        calleeServer.start();
        calleeBackchannelUri = "http://localhost:" + calleeServer.getAddress().getPort() + "/backchannel-logout";
    }

    @AfterAll
    static void stopCalleeServer() {
        calleeServer.stop(0);
    }

    private static void handleBackchannelLogoutRequest(HttpExchange exchange) throws IOException {
        try (InputStream body = exchange.getRequestBody()) {
            String raw = new String(body.readAllBytes(), StandardCharsets.UTF_8);
            calleeRequestBodies.offer(raw);
        }
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
    }

    @BeforeEach
    void cleanState() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");
        calleeRequestBodies.clear();

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));

        // DELTA-01 fallback (RegisteredClientBackchannelLogoutUriResolver): catálogo vacío por
        // defecto para que un client_id sin backchannel_logout_uri en ClientSettings no NPEe al
        // caer al fallback — mismo comportamiento que un adapter YAML real sin entradas.
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(java.util.Set.of()));
    }

    // =========================================================
    // AC-01: happy path — invalidación + cookie expirada + redirect + callee notificado
    // =========================================================
    @Test
    void singleLogout_terminatesSessionAndNotifiesCallee_onValidLogoutRequest() throws Exception {
        String initiatorClientId = "initiator-ac01";
        String calleeClientId = "callee-ac01";
        String sessionId = insertActiveSession(TENANT);
        insertSessionClient(sessionId, TENANT, initiatorClientId);
        insertSessionClient(sessionId, TENANT, calleeClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(calleeClientId, null, calleeBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ac01");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI))
                .andExpect(cookie().maxAge("__Secure-sso-" + TENANT, 0));

        assertThat(sessionState(sessionId)).isEqualTo("TERMINATED");

        String delivered = calleeRequestBodies.poll(3, TimeUnit.SECONDS);
        assertThat(delivered).as("callee debe recibir el logout_token").isNotNull();
        assertThat(delivered).contains("logout_token=");

        verify(auditPort, timeout(3000)).publish(argThatEvent(
                SsoAuditEvent.EventType.BACKCHANNEL_DELIVERED, calleeClientId));
    }

    // =========================================================
    // EC-01: doble logout — idempotente, sin re-dispatch en la segunda llamada
    // =========================================================
    @Test
    void singleLogout_isIdempotent_onDoubleLogoutRequest() throws Exception {
        String initiatorClientId = "initiator-ec01";
        String calleeClientId = "callee-ec01";
        String sessionId = insertActiveSession(TENANT);
        insertSessionClient(sessionId, TENANT, initiatorClientId);
        insertSessionClient(sessionId, TENANT, calleeClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(calleeClientId, null, calleeBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ec01");

        // Primera llamada: invalida de verdad, dispatch al callee.
        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        assertThat(calleeRequestBodies.poll(3, TimeUnit.SECONDS)).isNotNull();

        // Segunda llamada con el mismo id_token_hint/cookie: EC-01, no-op, sin re-dispatch.
        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, timeout(2000)).publish(argThatEvent(
                SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED, initiatorClientId, "noop"));

        assertThat(calleeRequestBodies.poll(500, TimeUnit.MILLISECONDS))
                .as("la segunda llamada no debe re-despachar al callee")
                .isNull();
    }

    // =========================================================
    // EC-02: único aplicativo vivo = iniciador — sin callees, sin dispatch
    // =========================================================
    @Test
    void singleLogout_withOnlyInitiatorAlive_doesNotDispatch() throws Exception {
        String initiatorClientId = "initiator-ec02";
        String sessionId = insertActiveSession(TENANT);
        insertSessionClient(sessionId, TENANT, initiatorClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ec02");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI));

        assertThat(sessionState(sessionId)).isEqualTo("TERMINATED");
        assertThat(calleeRequestBodies.poll(500, TimeUnit.MILLISECONDS))
                .as("sin callees vivos no debe haber dispatch")
                .isNull();
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

    /**
     * Guarda una {@link OAuth2Authorization} con un {@link OidcIdToken} sintético en el
     * {@link OAuth2AuthorizationService} real de la app: {@code OidcLogoutAuthenticationProvider}
     * resuelve {@code id_token_hint} vía {@code findByToken}, NO decodificando un JWT firmado
     * (verificado por bytecode) — no hace falta un token realmente firmado para este fixture.
     */
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

    private String insertActiveSession(String tenant) {
        String id = UUID.randomUUID().toString();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, "holder-" + id,
                now, now.plusHours(1), now);
        return id;
    }

    private void insertSessionClient(String sessionId, String tenant, String clientId) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session_client (session_id, tenant, client_id, first_seen_at, last_used_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                sessionId, tenant, clientId, now, now);
    }

    private String sessionState(String sessionId) {
        return jdbcTemplate.queryForObject(
                "SELECT state FROM sso_session WHERE id = ?", String.class, sessionId);
    }

    private SsoAuditEvent argThatEvent(SsoAuditEvent.EventType type, String clientId) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type && clientId.equals(event.getClientId()));
    }

    private SsoAuditEvent argThatEvent(SsoAuditEvent.EventType type, String clientId, String outcome) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type
                        && clientId.equals(event.getClientId())
                        && outcome.equals(event.getOutcome()));
    }
}
