package es.in2.vcverifier.sso.it;

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
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — ReuseSsoSession con base de datos real (Testcontainers).
 *
 * Escenarios cubiertos:
 *   AC-01  Happy path: sesión ACTIVE en BD → reutilización SSO → 3xx redirect.
 *   AC-02  Sin sesión: ID en cookie sin fila en BD → LOGIN_REQUIRED.
 *   AC-03  RP no elegible: sesión existe pero clientA no está en eligibleClientIds.
 *   AC-04  Cross-tenant: sesión de tenant-a accedida desde tenant-b → SSO_CROSS_TENANT_ATTEMPT.
 *   EC-01  Sesión expirada: fila ACTIVE con expires_at pasado → filtro SQL la excluye.
 *   EC-02  Sesión SUPERSEDED: fila con state='SUPERSEDED' → filtro SQL la excluye.
 *   ES-01  Fallo de almacén (fail-closed): spy lanza RuntimeException → SSO_PERSIST_ERROR.
 *   W5     Aislamiento cross-tenant a nivel de repositorio con DB real.
 *   Coex   prompt=login y ausencia de prompt → rama SSO no se activa.
 */
@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestClientConfig.class)
class ReuseSsoSessionIT {

    private static final String TENANT       = "tenant-a";
    private static final String CLIENT_ID    = "clientA";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String COOKIE_NAME  = "__Secure-sso-" + TENANT;
    private static final String X_TENANT     = "X-Tenant";

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

    @Autowired
    private java.util.Set<String> allowedClientsOrigins;

    // ── Mocks ──────────────────────────────────────────────────
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

    // ── Spy sobre la implementación real (para ES-01) ──────────
    @MockitoSpyBean
    private SsoSessionJdbcRepository sessionRepository;

    // =========================================================
    // SETUP
    // =========================================================

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sso_session (
                    id            TEXT        PRIMARY KEY,
                    tenant        TEXT        NOT NULL,
                    holder_hash   TEXT        NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL,
                    expires_at    TIMESTAMPTZ NOT NULL,
                    last_used_at  TIMESTAMPTZ NOT NULL,
                    state         VARCHAR(32) NOT NULL
                )
                """);
        jdbcTemplate.execute("DELETE FROM sso_session");

        reset(auditPort);

        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(defaultConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.systemDefault());
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of(CLIENT_ID))));
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
    }

    // =========================================================
    // AC-01 HAPPY PATH (ALLOWED)
    // Real DB: sesión ACTIVE con expires_at futuro → findActiveById la devuelve.
    // =========================================================
    @Test
    void should_reuse_session_and_redirect_when_active_session_exists_in_db() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-hash-01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("code=")));

        verify(sessionRepository, atLeastOnce())
                .findActiveById(any(SsoSessionId.class), anyString());
        verify(tenantSsoConfigPort, atLeastOnce())
                .getByTenant(anyString());
        // Asserts the ALLOWED outcome specifically — a 3xx redirect alone would also be produced
        // by a LOGIN_REQUIRED/INTERACTION_REQUIRED fallback, which is exactly what masked the
        // original SSO-reuse bug (the redirect always pointed to the QR login page instead).
        verify(auditPort, times(1)).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED
                        && "REUSED".equals(e.getOutcome())));
    }

    // =========================================================
    // SEC: redirect_uri con MISMO origen (ya en el allowlist) pero PATH distinto
    // al registrado para el cliente → nunca se emite code, aunque la sesión SSO
    // sea válida y el cliente esté en el catálogo. Regresión de seguridad
    // detectada en code-review: la ruta ALLOWED emitía el code confiando en el
    // redirect_uri crudo de la petición, validado solo a nivel de origen
    // (CustomErrorResponseHandler#isAllowedRedirectUri, que es global y
    // cross-client) pero NUNCA contra los redirectUris registrados de ESE
    // cliente en concreto (el control per-cliente y full-URI que
    // CustomAuthorizationRequestConverter#validateRedirectUri aplica en el
    // resto de flujos de este fichero). Usar el mismo origen que el registrado
    // reproduce exactamente el escenario explotable (pasa el allowlist de
    // origen, debe fallar el match per-cliente de URI completa).
    // =========================================================
    @Test
    void should_notIssueCode_whenRedirectUriPathNotRegisteredForClient() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-hash-sec01");
        // REDIRECT_URI = "https://localhost/callback" — mismo origen, path distinto
        allowedClientsOrigins.add("https://localhost");

        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "https://localhost/not-the-registered-path")
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("code="))));

        verify(auditPort, never()).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
        verify(auditPort, atLeastOnce()).publish(argThat(e ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "REDIRECT_URI_MISMATCH".equals(e.getOutcome())));
    }

    // =========================================================
    // AC-02 NO SESIÓN → LOGIN_REQUIRED
    // Real DB: el ID en cookie no coincide con ninguna fila ACTIVE.
    // =========================================================
    @Test
    void should_redirect_to_login_when_no_session_in_db() throws Exception {
        String unknownId = SsoSessionId.generate().getValue();

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, unknownId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(sessionRepository, atLeastOnce())
                .findActiveById(any(SsoSessionId.class), anyString());
    }

    // =========================================================
    // AC-03 RP NO ELEGIBLE → INTERACTION_REQUIRED + SSO_REUSE_DENIED
    // Real DB: sesión ACTIVE, pero clientA no está en eligibleClientIds.
    // =========================================================
    @Test
    void should_return_interaction_required_when_client_not_eligible() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-hash-03");

        TenantSsoConfig configNoClient = new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of(EligibleClientConfig.of("other-client"))
        );
        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(configNoClient));
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of("other-client"))));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED));
    }

    // =========================================================
    // AC-04 CROSS-TENANT → SSO_CROSS_TENANT_ATTEMPT
    // Real DB: sesión de tenant-a accedida desde tenant-b.
    // El workflow detecta el intento y emite SSO_CROSS_TENANT_ATTEMPT.
    // =========================================================
    @Test
    void should_emit_cross_tenant_event_when_session_belongs_to_different_tenant() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-hash-ct");

        // La request llega para tenant-b pero la cookie tiene una sesión de tenant-a
        when(tenantSsoConfigPort.getByTenant("tenant-b"))
                .thenReturn(Optional.of(new TenantSsoConfig(
                        "tenant-b", "domain", true,
                        new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                        List.of(EligibleClientConfig.of(CLIENT_ID))
                )));

        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, "tenant-b")
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", REDIRECT_URI)
                        .cookie(new Cookie("__Secure-sso-tenant-b", sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT));
    }

    // =========================================================
    // EC-01 SESIÓN EXPIRADA
    // Real DB: fila insertada con expires_at en el pasado (state = 'ACTIVE').
    // El filtro SQL "AND expires_at > now()" la excluye → findActiveById vacío.
    // =========================================================
    @Test
    void should_fall_back_when_session_expired_in_db() throws Exception {
        String sessionId = insertExpiredSession(TENANT, "expired-holder-01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        Integer activeCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE id = ? AND expires_at > NOW()",
                Integer.class, sessionId);
        assertThat(activeCount).isZero();
    }

    // =========================================================
    // EC-02 SESIÓN SUPERSEDED
    // Real DB: fila con state = 'SUPERSEDED' y expires_at futuro.
    // El filtro SQL "AND state = 'ACTIVE'" la excluye → findActiveById vacío.
    // =========================================================
    @Test
    void should_fall_back_when_session_is_superseded_in_db() throws Exception {
        String sessionId = insertSupersededSession(TENANT, "superseded-holder-01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        String state = jdbcTemplate.queryForObject(
                "SELECT state FROM sso_session WHERE id = ?", String.class, sessionId);
        assertThat(state).isEqualTo("SUPERSEDED");
    }

    // =========================================================
    // ES-01 FALLO ALMACÉN (FAIL-CLOSED)
    // El spy lanza RuntimeException en findActiveById.
    // El workflow captura la excepción, emite SSO_PERSIST_ERROR y devuelve
    // LOGIN_REQUIRED → 3xx redirect (fail-closed, sin exponer el error al RP).
    // =========================================================
    @Test
    void should_fail_closed_and_emit_audit_event_when_repository_throws() throws Exception {
        doThrow(new RuntimeException("DB down"))
                .when(sessionRepository).findActiveById(any(SsoSessionId.class), anyString());

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, SsoSessionId.generate().getValue()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(sessionRepository, atLeastOnce())
                .findActiveById(any(SsoSessionId.class), anyString());
        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR));
    }

    // =========================================================
    // W5 — AISLAMIENTO CROSS-TENANT A NIVEL DE REPOSITORIO (DB REAL)
    // Verifica directamente que findActiveById con tenant distinto devuelve vacío.
    // =========================================================
    @Test
    void findActiveById_returns_empty_when_session_belongs_to_different_tenant() {
        String sessionId = insertActiveSession(TENANT, "holder-hash-w5");

        Optional<SsoSession> result = sessionRepository.findActiveById(
                SsoSessionId.of(sessionId), "tenant-b");

        assertThat(result).isEmpty();
    }

    // =========================================================
    // COEXISTENCIA: prompt=login → rama SSO no se activa;
    // el flujo OID4VP estándar produce 3xx hacia la wallet.
    // =========================================================
    @Test
    void should_skip_sso_branch_when_prompt_is_login() throws Exception {
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, SsoSessionId.generate().getValue()))
                        .param("prompt", "login"))
                .andExpect(status().is3xxRedirection());

        verify(sessionRepository, never()).findActiveById(any(), any());
    }

    // =========================================================
    // COEXISTENCIA: sin parámetro prompt → flujo OID4VP estándar.
    // =========================================================
    @Test
    void should_skip_sso_branch_when_no_prompt_parameter() throws Exception {
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, SsoSessionId.generate().getValue())))
                .andExpect(status().is3xxRedirection());

        verify(sessionRepository, never()).findActiveById(any(), any());
    }

    // =========================================================
    // HELPERS — request builder base
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
    // HELPERS — configuración por defecto
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
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
    // HELPERS — inserción directa en BD usando SsoSessionId (TEXT)
    // =========================================================

    private String insertActiveSession(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                now,
                now.plusHours(1),
                now.minusMinutes(5)
        );
        // Snapshot de credencial que un establecimiento real habría dejado — necesario para que
        // la ruta ALLOWED emita el code en vez de caer a LOGIN_REQUIRED (ver ReuseSsoSessionWorkflowImpl).
        JsonNode fakeCredential = objectMapper.createObjectNode().put("sub", holderHash);
        ssoSessionCredentialCache.add(id, fakeCredential);
        return id;
    }

    private String insertExpiredSession(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime twoHoursAgo = OffsetDateTime.now(ZoneOffset.UTC).minusHours(2);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                twoHoursAgo,
                twoHoursAgo.plusMinutes(30),
                twoHoursAgo
        );
        return id;
    }

    private String insertSupersededSession(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'SUPERSEDED')
                """,
                id, tenant, holderHash,
                now.minusMinutes(30),
                now.plusMinutes(30),
                now.minusMinutes(30)
        );
        return id;
    }
}
