package es.in2.vcverifier.sso;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — Validez de sesiones SSO con TTL absoluto e idle a través del stack completo.
 *
 * AC-04  Sesión con expires_at pasado → filtro SQL la excluye → LOGIN_REQUIRED.
 * AC-05  Sesión con expires_at futuro pero idle excedido → isValid() false → LOGIN_REQUIRED.
 * EC-02  Reducir TTL en config no invalida sesiones vivas: el expiresAt almacenado
 *        en BD es autoritativo; la sesión se sigue reutilizando.
 */
@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SsoSessionTtlValidityIT {

    private static final String TENANT       = "tenant-a";
    private static final String CLIENT_ID    = "clientA";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String COOKIE_NAME  = "__Secure-sso-" + TENANT;
    private static final String X_TENANT     = "X-Tenant";
    private static final Duration IDLE_TTL   = Duration.ofMinutes(30);

    // =========================================================
    // TESTCONTAINERS
    // =========================================================

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url",          postgres::getJdbcUrl);
        registry.add("spring.flyway.user",         postgres::getUsername);
        registry.add("spring.flyway.password",     postgres::getPassword);
    }

    // =========================================================
    // SPRING BEANS
    // =========================================================

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private CacheStore<JsonNode> ssoSessionCredentialCache;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private TenantSsoConfigPort tenantSsoConfigPort;

    @MockitoBean
    private SsoAuditPort auditPort;

    @MockitoBean
    private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    @MockitoBean
    private ClientLoaderConfig clientLoaderConfig;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private DcqlProfileResolver dcqlProfileResolver;

    @MockitoBean
    private CustomErrorResponseHandler customErrorResponseHandler;

    @MockitoBean
    private ClientRegistryProvider clientRegistryProvider;

    // =========================================================
    // SETUP
    // =========================================================

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sso_session (
                    id             TEXT        PRIMARY KEY,
                    tenant         TEXT        NOT NULL,
                    holder_hash    TEXT        NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL,
                    expires_at     TIMESTAMPTZ NOT NULL,
                    last_used_at   TIMESTAMPTZ NOT NULL,
                    state          VARCHAR(32) NOT NULL
                )
                """);
        jdbcTemplate.execute("DELETE FROM sso_session");

        reset(auditPort);

        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(defaultConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(8), IDLE_TTL));
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of(CLIENT_ID))));
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
    }

    // =========================================================
    // AC-04: TTL absoluto vencido
    // La sesión tiene expires_at en el pasado; el filtro SQL "AND expires_at > now()"
    // la excluye → findActiveById devuelve vacío → LOGIN_REQUIRED.
    // =========================================================
    @Test
    void reuse_shouldReturnLoginRequired_whenAbsoluteTtlHasExpired() throws Exception {
        String sessionId = insertExpiredSession(TENANT, "holder-ac04");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // La fila existe pero ya no está dentro del rango activo
        Integer activeCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE id = ? AND expires_at > NOW()",
                Integer.class, sessionId);
        assertThat(activeCount).isZero();

        // No debe emitirse SSO_SESSION_REUSED
        verify(auditPort, never()).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // AC-05: Idle TTL excedido
    // expires_at está en el futuro (SQL pasa), pero last_used_at fue hace 35 min.
    // Con idleTtl=30 min → session.isValid(now, PT30M) == false → LOGIN_REQUIRED.
    // =========================================================
    @Test
    void reuse_shouldReturnLoginRequired_whenIdleTtlExceeded() throws Exception {
        String sessionId = insertSessionWithIdleExceeded(TENANT, "holder-ac05");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // La sesión existe y no está expirada a nivel SQL
        Integer activeCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE id = ? AND expires_at > NOW()",
                Integer.class, sessionId);
        assertThat(activeCount).isOne();

        // No debe emitirse SSO_SESSION_REUSED (el workflow devuelve LOGIN_REQUIRED en isValid)
        verify(auditPort, never()).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // EC-02: Reducir TTL en config no recalcula sesiones vivas
    // Sesión creada con absolute TTL=8h (established hace 30 min, expires en 7h30m).
    // Config actualizada a PT1H → el expiresAt almacenado (now+7h30m) sigue > now()
    // → SQL pasa, isValid pasa (idle 5min < 30min) → SSO_SESSION_REUSED.
    // =========================================================
    @Test
    void reuse_shouldStillAllowSession_whenConfigTtlReducedButStoredExpiresAtIsInFuture()
            throws Exception {
        String sessionId = insertSessionWith8hTtl(TENANT, "holder-ec02");

        // Simular que la config ha reducido el TTL absoluto a 1h
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(1), IDLE_TTL));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // El expiresAt almacenado (now+7h30m) es autoritativo; la sesión se reutiliza
        verify(auditPort, times(1)).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // HELPERS — request builder
    // =========================================================

    private MockHttpServletRequestBuilder baseRequest() {
        return get("/oidc/authorize")
                .header("X-Forwarded-Proto", "https")
                .header(X_TENANT, TENANT)
                .param("client_id", CLIENT_ID)
                .param("scope", "openid")
                .param("state", "xyz")
                .param("redirect_uri", REDIRECT_URI);
    }

    // =========================================================
    // HELPERS — config / client
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), IDLE_TTL),
                List.of(EligibleClientConfig.of(CLIENT_ID))
        );
    }

    private RegisteredClient buildClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .setting("tenant", TENANT)
                        .build())
                .build();
    }

    // =========================================================
    // HELPERS — inserción directa en BD
    // =========================================================

    /** AC-04: sesión con expires_at en el pasado (absoluto vencido). */
    private String insertExpiredSession(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                now.minusHours(9),
                now.minusMinutes(5),    // expires_at en el pasado → SQL la excluye
                now.minusHours(9)
        );
        return id;
    }

    /** AC-05: sesión con expires_at futuro pero last_used_at 35 min atrás (> IDLE_TTL=30 min). */
    private String insertSessionWithIdleExceeded(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                now.minusHours(1),
                now.plusHours(7),       // expires_at futuro → SQL pasa
                now.minusMinutes(35)    // idle = 35 min > IDLE_TTL (30 min)
        );
        return id;
    }

    /**
     * EC-02: sesión establecida hace 30 min con TTL original de 8h.
     * expiresAt = established_at + 8h = now - 30min + 8h = now + 7h30m.
     */
    private String insertSessionWith8hTtl(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime established = now.minusMinutes(30);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                established,
                established.plusHours(8), // expiresAt calculado con el TTL original de 8h
                now.minusMinutes(5)        // last_used_at: 5 min atrás (idle OK)
        );
        // Snapshot de credencial que un establecimiento real habría dejado — necesario para que
        // la ruta ALLOWED emita el code (ver ReuseSsoSessionWorkflowImpl).
        JsonNode fakeCredential = objectMapper.createObjectNode().put("sub", holderHash);
        ssoSessionCredentialCache.add(id, fakeCredential);
        return id;
    }
}
