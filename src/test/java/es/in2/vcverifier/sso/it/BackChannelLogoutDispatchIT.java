package es.in2.vcverifier.sso.it;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 AC-04: el {@code logout_token} entregado a un callee con canal declarado lleva
 * claims completos (iss/aud/sid/jti/events) y firma ES256 + {@code kid} válidos (mismo signer
 * EC P-256 de {@link CryptoComponent} usado por el resto de tokens del Verifier). Un callee sin
 * {@code backchannel_logout_uri} declarado (ni en {@code ClientSettings} ni en el catálogo
 * elegible) no recibe notificación — se emite {@code backchannel_skipped} con
 * {@code reason=no_backchannel_uri}.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class BackChannelLogoutDispatchIT {

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
    @Autowired private CryptoComponent cryptoComponent;

    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    private static HttpServer calleeServer;
    private static LinkedBlockingQueue<String> calleeRequestBodies;
    private static String calleeBackchannelUri;

    @BeforeAll
    static void startCalleeServer() throws IOException {
        calleeRequestBodies = new LinkedBlockingQueue<>();
        calleeServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        calleeServer.createContext("/backchannel-logout", BackChannelLogoutDispatchIT::handleRequest);
        calleeServer.start();
        calleeBackchannelUri = "http://localhost:" + calleeServer.getAddress().getPort() + "/backchannel-logout";
    }

    @AfterAll
    static void stopCalleeServer() {
        calleeServer.stop(0);
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        calleeRequestBodies.offer(raw);
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
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(Set.of()));
    }

    // =========================================================
    // AC-04: callee CON canal declarado — logout_token con claims completos + firma ES256/kid válidos.
    // =========================================================
    @Test
    void singleLogout_deliversSignedLogoutToken_toCalleeWithDeclaredChannel() throws Exception {
        String initiatorClientId = "initiator-ac04";
        String calleeClientId = "callee-ac04-with-channel";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, calleeClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(calleeClientId, null, calleeBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ac04");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        String rawBody = calleeRequestBodies.poll(3, TimeUnit.SECONDS);
        assertThat(rawBody).as("el callee con canal declarado debe recibir el logout_token").isNotNull();

        String logoutTokenJwt = extractLogoutTokenParam(rawBody);
        SignedJWT signedJwt = SignedJWT.parse(logoutTokenJwt);

        // Firma ES256 + kid — mismo signer EC P-256 que el resto de tokens del Verifier.
        assertThat(signedJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        ECKey signingKey = cryptoComponent.getECKey();
        assertThat(signedJwt.getHeader().getKeyID()).isEqualTo(signingKey.getKeyID());
        assertThat(signedJwt.verify(new ECDSAVerifier(signingKey.toECPublicKey())))
                .as("la firma del logout_token debe verificar con la clave pública del Verifier")
                .isTrue();

        // Claims OIDC Back-Channel Logout 1.0 §2.4 — completos, sin nonce.
        var claims = signedJwt.getJWTClaimsSet();
        assertThat(claims.getAudience()).containsExactly(calleeClientId);
        assertThat(claims.getStringClaim("sid")).isEqualTo(sessionId);
        assertThat(claims.getStringClaim("jti")).isNotBlank();
        assertThat(claims.getStringClaim("iss")).isNotBlank();
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getClaim("nonce")).as("el logout_token nunca lleva nonce").isNull();

        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) claims.getClaim("events");
        assertThat(events).containsKey("http://schemas.openid.net/event/backchannel-logout");

        verify(auditPort, timeout(3000)).publish(argThatEventType(
                SsoAuditEvent.EventType.BACKCHANNEL_DELIVERED, calleeClientId));
    }

    // =========================================================
    // AC-04: callee SIN canal declarado — sin dispatch, backchannel_skipped/no_backchannel_uri.
    // =========================================================
    @Test
    void singleLogout_skipsCallee_whenNoBackchannelUriDeclared() throws Exception {
        String initiatorClientId = "initiator-ac04b";
        String calleeClientId = "callee-ac04b-no-channel";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, calleeClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(calleeClientId, null, null); // sin backchannel_logout_uri
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ac04b");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, timeout(3000)).publish(argThatEventTypeOutcomeAndReason(
                SsoAuditEvent.EventType.BACKCHANNEL_SKIPPED, calleeClientId, "skipped", "no_backchannel_uri"));

        assertThat(calleeRequestBodies.poll(500, TimeUnit.MILLISECONDS))
                .as("un callee sin canal declarado nunca debe recibir el logout_token")
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

    /** El cuerpo capturado es {@code logout_token=<jwt-url-encoded>} (form-urlencoded). */
    private String extractLogoutTokenParam(String rawBody) {
        String prefix = "logout_token=";
        assertThat(rawBody).startsWith(prefix);
        return URLDecoder.decode(rawBody.substring(prefix.length()), StandardCharsets.UTF_8);
    }

    private SsoAuditEvent argThatEventType(SsoAuditEvent.EventType type, String clientId) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type && clientId.equals(event.getClientId()));
    }

    private SsoAuditEvent argThatEventTypeOutcomeAndReason(
            SsoAuditEvent.EventType type, String clientId, String outcome, String reason) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type
                        && clientId.equals(event.getClientId())
                        && outcome.equals(event.getOutcome())
                        && reason.equals(event.getReason()));
    }
}
