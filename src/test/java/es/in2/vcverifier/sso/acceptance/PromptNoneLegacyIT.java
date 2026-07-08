package es.in2.vcverifier.sso.acceptance;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
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
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — prompt=none sobre tenant legacy (ssoEnabled=false).
 *
 * AC-03  GET /oidc/authorize?prompt=none con tenant legacy
 *        → 302 a redirect_uri?error=login_required; sin error 500 ni render de QR.
 * ES-02  Cookie de sesión SSO presentada a tenant legacy → cookie ignorada + login_required;
 *        sin emisión de code/id_token; sin filtrado de info de sesión de otro tenant.
 */
@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PromptNoneLegacyIT {

    private static final String LEGACY_TENANT = "tenant-legacy";
    private static final String SSO_TENANT    = "tenant-sso";
    private static final String CLIENT_ID     = "clientA";
    private static final String REDIRECT_URI  = "https://localhost/callback";
    private static final String COOKIE_PREFIX = "__Secure-sso-";
    private static final String X_TENANT      = "X-Tenant";

    // TTLs mínimos ADR-106
    private static final Duration ABS_TTL  = Duration.ofHours(1);
    private static final Duration IDLE_TTL = Duration.ofMinutes(5);

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
                .thenReturn(Optional.of(legacyConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(ABS_TTL, IDLE_TTL));
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.empty());
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
    }

    // =========================================================
    // AC-03: prompt=none + tenant legacy, sin cookie
    // → 302 a redirect_uri?error=login_required; sin 500 ni render de QR.
    // Con ssoEnabled=false el workflow cortocircuita antes de consultar BD ni catálogo.
    // =========================================================
    @Test
    void should_redirectWithLoginRequired_noCookie_whenLegacyTenantAndPromptNone() throws Exception {
        // Given: a legacy tenant (sso.enabled=false, stubbed in setUp) and a prompt=none request without SSO cookie

        // When
        mockMvc.perform(baseRequest().param("prompt", "none"))
                // Then: 302 to redirect_uri with error=login_required
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")))
                .andExpect(header().string("Location", containsString("state=xyz")));

        // And: the catalog is not consulted and no SSO session reuse is audited
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // AC-03 (config ausente / B1): tenant SIN entrada tenant_sso — el default de todo tenant no
    // migrado — con prompt=none → 302 a redirect_uri?error=login_required, SIN HTTP 500.
    // Regresión: reuse() hacía orElseThrow(IllegalStateException) desde el filtro de seguridad
    // (no interceptable por @RestControllerAdvice); ahora hace fail-closed a login_required.
    // =========================================================
    @Test
    void should_redirectWithLoginRequired_whenLegacyTenantConfigAbsentAndPromptNone() throws Exception {
        // Given: a legacy tenant with no config entry (getByTenant empty) and a prompt=none request
        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.empty());

        // When
        mockMvc.perform(baseRequest().param("prompt", "none"))
                // Then: 302 to redirect_uri with error=login_required (no HTTP 500)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")));

        // And: no SSO session reuse is audited
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // ES-02 COOKIE IGNORADA: sesión activa en BD para el tenant legacy +
    // cookie presente → cookie ignorada; ssoEnabled=false cortocircuita antes
    // de cualquier acceso a la sesión. Respuesta: 302 a redirect_uri?error=login_required.
    // =========================================================
    @Test
    void should_ignoreCookieAndReturnLoginRequired_whenLegacyTenantWithActiveCookieAndPromptNone()
            throws Exception {
        // Given: a legacy tenant with an active SSO session in DB and a residual SSO cookie
        String sessionId = insertActiveSession(LEGACY_TENANT, "holder-es02");

        // When: prompt=none carrying the cookie
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_PREFIX + LEGACY_TENANT, sessionId))
                        .param("prompt", "none"))
                // Then: cookie ignored → 302 to redirect_uri with error=login_required
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")));

        // And: ssoEnabled=false short-circuits before touching the catalog or the session store; no reuse
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // ES-02 SIN CODE NI ID_TOKEN: con cookie de sesión activa y tenant legacy
    // → Location es redirect_uri?error=login_required, sin code ni id_token.
    // Verifica que el flujo no emite credenciales OAuth2/OIDC aunque la sesión
    // exista en BD (la cookie es ignorada porque ssoEnabled=false).
    // =========================================================
    @Test
    void should_notEmitCodeOrToken_whenLegacyTenantWithActiveCookieAndPromptNone()
            throws Exception {
        // Given: a legacy tenant with an active SSO session in DB and a residual SSO cookie
        String sessionId = insertActiveSession(LEGACY_TENANT, "holder-es02-token");

        // When: prompt=none carrying the cookie
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_PREFIX + LEGACY_TENANT, sessionId))
                        .param("prompt", "none"))
                // Then: 302 with error=login_required and neither code nor id_token issued
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")))
                .andExpect(header().string("Location", not(containsString("code="))))
                .andExpect(header().string("Location", not(containsString("id_token="))));
    }

    // =========================================================
    // ES-02 AISLAMIENTO CROSS-TENANT: cookie de sesión de un tenant SSO habilitado
    // enviada a una request para el tenant legacy.
    // El extractor de cookies solo busca __Secure-sso-tenant-legacy, por lo que la
    // cookie de SSO_TENANT no casa (cookieValue=null). Con ssoEnabled=false el
    // workflow cortocircuita sin acceder a la sesión del otro tenant.
    // Respuesta: 302 a redirect_uri?error=login_required.
    // No se emite SSO_CROSS_TENANT_ATTEMPT ni SSO_SESSION_REUSED.
    // =========================================================
    @Test
    void should_notLeakCrossTenantSession_whenCookieFromSsoTenantSentToLegacyTenant()
            throws Exception {
        // Given: an active session for an SSO tenant, whose cookie is sent to a legacy-tenant request
        String ssoSessionId = insertActiveSession(SSO_TENANT, "holder-sso");

        // When: prompt=none for the legacy tenant carrying the other tenant's cookie
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_PREFIX + SSO_TENANT, ssoSessionId))
                        .param("prompt", "none"))
                // Then: cookie name doesn't match → ignored → 302 with error=login_required
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")));

        // And: no cross-tenant attempt nor session reuse is audited
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT));
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // HELPERS — request builder base
    // =========================================================

    private MockHttpServletRequestBuilder baseRequest() {
        return get("/oidc/authorize")
                .header("X-Forwarded-Proto", "https")
                .header(X_TENANT, LEGACY_TENANT)
                .param("client_id", CLIENT_ID)
                .param("scope", "openid")
                .param("state", "xyz")
                .param("redirect_uri", REDIRECT_URI);
    }

    // =========================================================
    // HELPERS — configuración y cliente por defecto
    // =========================================================

    private TenantSsoConfig legacyConfig() {
        return new TenantSsoConfig(
                LEGACY_TENANT, "legacy-domain.com", false,
                new TenantSsoConfig.SsoTtlConfig(ABS_TTL, IDLE_TTL),
                List.of()
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
                        .setting("tenant", LEGACY_TENANT)
                        .build())
                .build();
    }

    // =========================================================
    // HELPERS — inserción directa en BD
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
                now.minusMinutes(30),
                now.plusMinutes(30),
                now.minusMinutes(2)
        );
        return id;
    }
}
