package es.in2.vcverifier.sso.it;

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
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 ES-03: un callee que nunca responde (más allá de los 5s de timeout por intento de
 * {@code BackChannelLogoutDispatcher}) se trata como fallo con {@code reason=timeout} — no
 * bloquea indefinidamente el worker de dispatch asíncrono ni retrasa la redirección al iniciador.
 * <p>
 * Nota de duración: el timeout de 5s por intento (ES-03) es una constante de producción, no
 * configurable desde el test — este IT toma inevitablemente ~15-20s (3 intentos agotados) para
 * completar la verificación del {@code backchannel_failed} final, aunque la redirección al
 * iniciador se mide y confirma en milisegundos.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class BackChannelLogoutTimeoutIT {

    private static final String TENANT = "tenant-a";
    private static final String POST_LOGOUT_REDIRECT_URI = "https://initiator.example.com/logged-out";
    // Por debajo de los 5s de timeout del dispatcher pero suficiente para que el cliente
    // HTTP siempre agote su propio timeout antes de que el callee responda.
    private static final long CALLEE_HANG_MS = 7000L;

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

    private static HttpServer hangingServer;
    private static String hangingBackchannelUri;

    @BeforeAll
    static void startHangingCalleeServer() throws IOException {
        hangingServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        // Executor multi-hilo: cada intento de retry debe poder aceptarse en paralelo al
        // anterior (que sigue "colgado"), igual que un servidor real bajo carga.
        hangingServer.setExecutor(Executors.newCachedThreadPool());
        hangingServer.createContext("/backchannel-logout", exchange -> {
            exchange.getRequestBody().readAllBytes();
            try {
                Thread.sleep(CALLEE_HANG_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // Para cuando llega aquí el cliente ya habrá agotado su propio timeout (5s);
            // esta respuesta tardía no la lee nadie, pero cerramos limpio igualmente.
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        hangingServer.start();
        hangingBackchannelUri = "http://localhost:" + hangingServer.getAddress().getPort() + "/backchannel-logout";
    }

    @AfterAll
    static void stopCalleeServer() {
        hangingServer.stop(0);
    }

    @BeforeEach
    void cleanState() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(Set.of()));
    }

    // =========================================================
    // ES-03: callee que nunca responde — timeout tratado como fallo, iniciador no bloqueado.
    // =========================================================
    @Test
    void singleLogout_treatsHangingCalleeAsTimeoutFailure_withoutBlockingInitiator() throws Exception {
        String initiatorClientId = "initiator-es03";
        String hangingClientId = "callee-es03-hanging";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, hangingClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(hangingClientId, null, hangingBackchannelUri);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-es03");

        Instant start = Instant.now();

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI));

        Duration elapsed = Duration.between(start, Instant.now());
        assertThat(elapsed)
                .as("un callee colgado nunca debe retrasar la redirección al iniciador")
                .isLessThan(Duration.ofSeconds(1));

        // 3 intentos x 5s de timeout + backoff entre intentos ≈ 16.5s — margen amplio.
        verify(auditPort, timeout(25000)).publish(argThatEventTypeAndOutcome(
                SsoAuditEvent.EventType.BACKCHANNEL_FAILED, hangingClientId, "timeout"));
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

    private SsoAuditEvent argThatEventTypeAndOutcome(SsoAuditEvent.EventType type, String clientId, String outcome) {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == type
                        && clientId.equals(event.getClientId())
                        && outcome.equals(event.getOutcome()));
    }
}
