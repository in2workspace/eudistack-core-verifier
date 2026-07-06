package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
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
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — Catálogo SSO y elegibilidad de clientes (US-05).
 *
 * AC-01  Reuse concedido a RP presente en el catálogo.
 * AC-02  interaction_required para RP fuera del catálogo (CATALOG_REJECTED).
 * AC-03  interaction_required con catálogo vacío — fail-closed.
 * AC-05  Cliente no registrado en el servidor OAuth2 → error antes del catálogo.
 * EC-02  Alta posterior al establecimiento de sesión evalúa la config vigente.
 * EC-03  Tenant legacy sso.enabled=false → flujo OID4VP sin 500.
 * EC-01  Sesión expirada (abs TTL) en catálogo → login_required, no interaction_required.
 */
@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TenantSsoCatalogReuseIT {

    private static final String TENANT       = "tenant-a";
    private static final String CLIENT_ID    = "clientA";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String COOKIE_NAME  = "__Secure-sso-" + TENANT;
    private static final String X_TENANT     = "X-Tenant";

    // TTL mínimos ADR-106: 1h abs / 5min idle — suficiente para los escenarios no-expirado
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
                .thenReturn(Optional.of(defaultConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(ABS_TTL, IDLE_TTL));
        // US-05: catálogo con CLIENT_ID por defecto — override en tests específicos
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(catalogWith(CLIENT_ID));
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
    }

    // =========================================================
    // AC-01 HAPPY PATH: RP en catálogo → reuse concedido
    // Sesión ACTIVE, CLIENT_ID en catálogo → SSO_SESSION_REUSED.
    // =========================================================
    @Test
    void should_reuseSession_andEmitAudit_whenClientIsInCatalog() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-ac01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
        verify(tenantSsoConfigPort, atLeastOnce()).resolveEligibleClients(anyString());
    }

    // =========================================================
    // AC-02 RP FUERA DEL CATÁLOGO → interaction_required
    // Sesión ACTIVE, CLIENT_ID NO está en catálogo (otro-client sí) →
    // REJECT_CATALOG → SSO_REUSE_DENIED con outcome CATALOG_REJECTED.
    // =========================================================
    @Test
    void should_returnInteractionRequired_whenClientNotInCatalog() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-ac02");

        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(catalogWith("other-client"));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "CATALOG_REJECTED".equals(event.getOutcome())));
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // AC-03 CATÁLOGO VACÍO → fail-closed → interaction_required
    // Sesión ACTIVE, catálogo vacío → TenantSsoCatalog.empty() →
    // contains() siempre false → REJECT_CATALOG → CATALOG_REJECTED.
    // =========================================================
    @Test
    void should_returnInteractionRequired_whenCatalogIsEmpty() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-ac03");

        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.empty());

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "CATALOG_REJECTED".equals(event.getOutcome())));
    }

    // =========================================================
    // AC-05 CLIENTE NO REGISTRADO → error OAuth2 antes del catálogo
    // registeredClientRepository devuelve null → el servidor OAuth2 rechaza
    // la solicitud con invalid_client antes de que el catálogo sea consultado.
    // =========================================================
    @Test
    void should_notConsultCatalog_whenClientIsNotRegistered() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-ac05");

        // Cliente desconocido para el servidor OAuth2 → invalid_client
        when(registeredClientRepository.findByClientId(anyString())).thenReturn(null);

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is4xxClientError()); // Spring AuthServer: invalid_client

        // El catálogo nunca se consulta porque el flujo SSO no llega al paso 5
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
    }

    // =========================================================
    // EC-02 CONFIG VIGENTE: alta posterior al establecimiento de sesión
    // Primera solicitud con catálogo vacío → CATALOG_REJECTED.
    // Tras "añadir" el cliente al catálogo (re-stub), segunda solicitud → ALLOWED.
    // Prueba que la config se re-lee en cada solicitud (sin caché estancada).
    // =========================================================
    @Test
    void should_evaluateCurrentCatalog_whenClientAddedAfterSessionEstablishment() throws Exception {
        String sessionId = insertActiveSession(TENANT, "holder-ec02");

        // Catálogo inicial sin CLIENT_ID → interaction_required
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.empty());

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "CATALOG_REJECTED".equals(event.getOutcome())));

        // "Alta posterior": config actualizada con CLIENT_ID
        reset(auditPort);
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(catalogWith(CLIENT_ID));

        // Segunda solicitud con la misma sesión → config vigente → ALLOWED
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
    }

    // =========================================================
    // EC-03 TENANT LEGACY sso.enabled=false → flujo OID4VP estándar, sin 500
    // Un tenant con SSO deshabilitado no produce error: el workflow devuelve
    // LOGIN_REQUIRED y el flujo OID4VP estándar produce una redirección normal.
    // =========================================================
    @Test
    void should_notFail_whenTenantHasSsoDisabled() throws Exception {
        TenantSsoConfig legacyConfig = new TenantSsoConfig(
                TENANT, "domain", false,
                new TenantSsoConfig.SsoTtlConfig(ABS_TTL, IDLE_TTL),
                List.of()
        );
        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(legacyConfig));

        // No se inserta sesión ni se envía cookie — el flujo SSO no se activa
        mockMvc.perform(baseRequest()
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_REUSED));
        // El catálogo no se consulta cuando SSO está deshabilitado
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
    }

    // =========================================================
    // EC-01 SESIÓN EXPIRADA (abs TTL policy) → login_required, no interaction_required
    // Sesión: established_at = ahora-2h, expires_at = ahora+6h (SQL pasa),
    //         last_used_at = ahora-2min (idle OK con 5min).
    // Config abs TTL = 1h → policy: now > established + 1h → REJECT_SESSION.
    // Aunque CLIENT_ID está en catálogo, la política corta en condición (2) antes de (3).
    // =========================================================
    @Test
    void should_returnLoginRequired_notInteractionRequired_whenSessionExpiredInPolicy() throws Exception {
        // Sesión con expires_at futuro (SQL pasa) pero TTL policy vencida (established hace 2h)
        String sessionId = insertSessionExpiredInPolicy(TENANT, "holder-ec01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // Debe emitirse SSO_REUSE_DENIED con outcome REJECT_SESSION, no CATALOG_REJECTED
        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "REJECT_SESSION".equals(event.getOutcome())));
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_REUSE_DENIED
                        && "CATALOG_REJECTED".equals(event.getOutcome())));
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
    // HELPERS — configuración y cliente por defecto
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(ABS_TTL, IDLE_TTL),
                List.of(CLIENT_ID)
        );
    }

    private TenantSsoCatalog catalogWith(String... clientIds) {
        List<SsoEligibleClient> clients = List.of(clientIds).stream()
                .map(SsoEligibleClient::of)
                .toList();
        return TenantSsoCatalog.of(clients);
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

    /** Sesión ACTIVE con expires_at futuro y last_used_at reciente (idle OK). */
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

    /**
     * EC-01: sesión con expires_at en el futuro (SQL pasa) pero establecida hace 2h.
     * Con abs TTL = 1h, la policy detecta: now > established_at + 1h → REJECT_SESSION.
     * last_used_at reciente para que el idle check pase.
     */
    private String insertSessionExpiredInPolicy(String tenant, String holderHash) {
        String id = SsoSessionId.generate().getValue();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime established = now.minusHours(2);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                established,
                now.plusHours(6),    // expires_at futuro → SQL pasa
                now.minusMinutes(2)  // idle reciente → isValid pasa
        );
        return id;
    }
}
