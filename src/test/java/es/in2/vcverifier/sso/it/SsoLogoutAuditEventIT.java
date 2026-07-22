package es.in2.vcverifier.sso.it;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.Constants;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 AC-06 / NFR-S-551-01 / NFR-S-551-02: un Single Logout completo (con un callee
 * entregado y otro sin canal declarado) emite el rastro de auditoría completo —
 * {@code sso_logout_initiated} + {@code backchannel_delivered}/{@code backchannel_skipped} —
 * con {@code tenant}/{@code client_id}/{@code correlation_id}/{@code outcome} correlacionables,
 * y NUNCA loggea el {@code session_id} completo (solo su prefijo de 8 chars).
 * <p>
 * A diferencia de las ITs de Tasks 14-22 (que mockean {@code SsoAuditPort} para simplificar
 * las aserciones de tipo de evento), esta IT usa el {@link SsoAuditAdapter} REAL con un
 * {@code ListAppender} de Logback (mismo patrón que Task 13) para inspeccionar el log
 * efectivamente emitido — es la única forma de verificar de extremo a extremo que
 * NFR-S-551-02 se cumple en un flujo real, no solo a nivel de unit test del adapter.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SsoLogoutAuditEventIT {

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
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    // SsoAuditPort NO se mockea — usamos el adapter real + ListAppender (ver javadoc de clase).
    private ListAppender<ILoggingEvent> logAppender;
    private Logger auditAdapterLogger;

    private static HttpServer deliveredCalleeServer;
    private static String deliveredBackchannelUri;

    @BeforeAll
    static void startDeliveredCalleeServer() throws IOException {
        deliveredCalleeServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        deliveredCalleeServer.createContext("/backchannel-logout", SsoLogoutAuditEventIT::handleOk);
        deliveredCalleeServer.start();
        deliveredBackchannelUri =
                "http://localhost:" + deliveredCalleeServer.getAddress().getPort() + "/backchannel-logout";
    }

    private static void handleOk(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
    }

    @AfterAll
    static void stopCalleeServer() {
        deliveredCalleeServer.stop(0);
    }

    @BeforeEach
    void setUp() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");

        auditAdapterLogger = (Logger) LoggerFactory.getLogger(SsoAuditAdapter.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        auditAdapterLogger.addAppender(logAppender);

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(es.in2.vcverifier.sso.domain.model.TenantSsoCatalog.of(Set.of()));
    }

    @AfterEach
    void tearDown() {
        auditAdapterLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    // =========================================================
    // AC-06 / NFR-S-551-01 / NFR-S-551-02: rastro completo, correlacionable, sin fuga de session_id.
    // =========================================================
    @Test
    void singleLogout_emitsFullAuditTrail_withoutLeakingFullSessionId() throws Exception {
        String initiatorClientId = "initiator-ac06";
        String deliveredClientId = "callee-ac06-delivered";
        String skippedClientId = "callee-ac06-skipped";
        String sessionId = insertActiveSession();
        insertSessionClient(sessionId, initiatorClientId);
        insertSessionClient(sessionId, deliveredClientId);
        insertSessionClient(sessionId, skippedClientId);

        RegisteredClient initiator = registerClient(initiatorClientId, POST_LOGOUT_REDIRECT_URI, null);
        registerClient(deliveredClientId, null, deliveredBackchannelUri);
        registerClient(skippedClientId, null, null);
        when(registeredClientRepository.findById(initiator.getId())).thenReturn(initiator);

        String idTokenHint = saveIdTokenAuthorization(initiator, "subject-ac06");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", initiatorClientId))
                .andExpect(status().is3xxRedirection());

        // Esperar a que el rastro completo (incluido el dispatch async) esté disponible.
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            List<String> logs = capturedMessages();
            assertThat(logs).anyMatch(m -> m.contains("SSO_LOGOUT_INITIATED"));
            assertThat(logs).anyMatch(m -> m.contains("BACKCHANNEL_DELIVERED"));
            assertThat(logs).anyMatch(m -> m.contains("BACKCHANNEL_SKIPPED"));
        });

        List<String> logs = capturedMessages();

        String initiatedLine = findLine(logs, "SSO_LOGOUT_INITIATED");
        assertThat(initiatedLine).contains("tenant=" + TENANT).contains("clientId=" + initiatorClientId)
                .contains("outcome=success").contains("correlationId=");

        String deliveredLine = findLine(logs, "BACKCHANNEL_DELIVERED");
        assertThat(deliveredLine).contains("tenant=" + TENANT).contains("clientId=" + deliveredClientId)
                .contains("outcome=success").contains("correlationId=");

        String skippedLine = findLine(logs, "BACKCHANNEL_SKIPPED");
        assertThat(skippedLine).contains("tenant=" + TENANT).contains("clientId=" + skippedClientId)
                .contains("outcome=skipped").contains("reason=no_backchannel_uri").contains("correlationId=");

        // NFR-S-551-02: el session_id completo NUNCA debe aparecer en ningún log — solo su
        // prefijo de 8 chars (que sí debe aparecer, para trazabilidad).
        assertThat(logs).noneMatch(m -> m.contains(sessionId));
        assertThat(logs).anyMatch(m -> m.contains("sessionIdPrefix=" + sessionId.substring(0, 8)));
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private List<String> capturedMessages() {
        return logAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private String findLine(List<String> logs, String marker) {
        return logs.stream().filter(m -> m.contains(marker)).findFirst()
                .orElseThrow(() -> new AssertionError("No se encontró línea de log con " + marker));
    }

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
}
