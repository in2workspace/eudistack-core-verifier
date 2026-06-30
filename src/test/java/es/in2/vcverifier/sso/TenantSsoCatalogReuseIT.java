package es.in2.vcverifier.sso;

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
import es.in2.vcverifier.sso.domain.service.TenantSsoPolicy;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.sso.it.TestClientConfig;
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
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT de catálogo SSO — Spring Boot + MockMvc + Testcontainers PostgreSQL.
 *
 * Diferencia clave con ReuseSsoSessionIT:
 *   - Se mocka tenantSsoConfigPort.resolveEligibleClients() para controlar
 *     TenantSsoCatalog con independencia del almacén YAML.
 *   - TenantSsoPolicy es un spy: para AC-05 se fuerza REJECT_SESSION; en el
 *     resto de escenarios corre la implementación real.
 *   - SsoSessionJdbcRepository es spy sobre PostgreSQL real (Testcontainers).
 *
 * Escenarios cubiertos:
 *   AC-01  Reuse concedido: sesión ACTIVE, clientA en catálogo → SSO_SESSION_ESTABLISHED.
 *   AC-02  interaction_required: sesión ACTIVE, clientA fuera del catálogo.
 *   AC-03  interaction_required: catálogo vacío (fail-closed TenantSsoCatalog.empty()).
 *   AC-05  login_required antes del catálogo: policy devuelve REJECT_SESSION → el
 *          motivo de rechazo es de sesión, no de catálogo, aunque clientA esté en él.
 *   EC-01  login_required (no interaction_required): sesión expirada — el SQL la excluye
 *          antes de que se evalúe el catálogo.
 *   EC-02  Alta posterior evalúa config vigente: primer intento falla (catálogo sin clientA),
 *          segundo intento concede el reuse tras actualizar el mock.
 *   EC-03  Tenant legacy sso.enabled=false → flujo OID4VP sin 500.
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
class TenantSsoCatalogReuseIT {

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

    // Spy sobre repositorio real para verificar interacciones con la BD
    @MockitoSpyBean
    private SsoSessionJdbcRepository sessionRepository;

    // Spy sobre policy real: permite forzar REJECT_SESSION en AC-05 sin alterar
    // el comportamiento natural del resto de escenarios.
    @MockitoSpyBean
    private TenantSsoPolicy ssoPolicy;

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

        reset(auditPort, ssoPolicy);

        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(defaultConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(1), Duration.ofMinutes(10)));
        // Catálogo por defecto: clientA elegible (sobrescrito por cada escenario que lo necesite).
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(List.of(CLIENT_ID)));
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
    }

    // =========================================================
    // AC-01: reuse concedido a RP en catálogo
    // Sesión ACTIVE, clientA en catálogo → policy.Allowed → SSO_SESSION_ESTABLISHED.
    // =========================================================

    @Test
    void should_allow_reuse_when_session_active_and_client_in_catalog() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ac01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED
                && "REUSED".equals(event.getOutcome())));
    }

    // =========================================================
    // AC-02: interaction_required a RP fuera del catálogo
    // Sesión ACTIVE, clientA NO en catálogo → REJECT_CATALOG → interaction_required.
    // =========================================================

    @Test
    void should_return_interaction_required_when_client_not_in_catalog() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ac02");

        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(List.of("other-client")));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=interaction_required")));

        // El reuse no se concede: no debe publicarse SSO_SESSION_ESTABLISHED.
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED));
    }

    // =========================================================
    // AC-03: interaction_required con catálogo vacío (fail-closed)
    // TenantSsoCatalog.empty().contains() siempre false → REJECT_CATALOG.
    // =========================================================

    @Test
    void should_return_interaction_required_when_catalog_is_empty() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ac03");

        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.empty());

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=interaction_required")));

        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED));
    }

    // =========================================================
    // AC-05: cliente no registrado → REJECT_SESSION antes que catálogo
    //
    // La condición (1) de TenantSsoPolicy (cliente en RegisteredClientRepository)
    // se evalúa antes que (3) catalog.contains(). Se fuerza REJECT_SESSION vía spy
    // para verificar que el resultado es login_required (no interaction_required)
    // aunque clientA esté presente en el catálogo.
    // =========================================================

    @Test
    void should_return_login_required_not_interaction_required_when_client_not_registered() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ac05");

        doReturn(TenantSsoPolicy.Decision.rejected(TenantSsoPolicy.RejectReason.REJECT_SESSION))
                .when(ssoPolicy).evaluate(eq(CLIENT_ID), any(), any(), any());

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")));

        // El catálogo SÍ se resuelve (el workflow lo obtiene antes de invocar policy.evaluate),
        // pero la causa de rechazo es SESSION, no CATALOG.
        verify(tenantSsoConfigPort, atLeastOnce()).resolveEligibleClients(anyString());
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED));
    }

    // =========================================================
    // EC-01: sesión expirada en catálogo → login_required, NO interaction_required
    //
    // Fila ACTIVE con expires_at en el pasado → SQL la excluye → findActiveById vacío
    // → excepción capturada → SSO_PERSIST_ERROR + LOGIN_REQUIRED.
    // El catálogo no llega a consultarse porque el cortocircuito ocurre antes.
    // =========================================================

    @Test
    void should_return_login_required_not_interaction_required_when_session_expired_and_client_in_catalog()
            throws Exception {
        UUID sessionId = insertExpiredSession(TENANT, "holder-ec01");

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=login_required")));

        // Sesión expirada excluida por SQL → el catálogo nunca se consulta.
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
        // El evento de auditoría es SSO_PERSIST_ERROR (sesión no encontrada), no REUSED.
        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR));
    }

    // =========================================================
    // EC-02: alta posterior al establecimiento de sesión evalúa config vigente
    //
    // Primera solicitud: clientA fuera del catálogo → interaction_required.
    // Simulación de alta en catálogo (actualización de mock de resolveEligibleClients).
    // Segunda solicitud: reuse concedido.
    // =========================================================

    @Test
    void should_allow_reuse_after_client_is_added_to_catalog() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ec02");

        // Primera solicitud: clientA NO en catálogo → interaction_required.
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(List.of("other-client")));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=interaction_required")));

        // Simulación de alta vía ManageTenantSsoCatalogService → el adaptador de config
        // devuelve ahora el catálogo actualizado con clientA.
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(List.of(CLIENT_ID)));

        // Segunda solicitud con la misma sesión activa: reuse concedido.
        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("error="))));

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED
                && "REUSED".equals(event.getOutcome())));
    }

    // =========================================================
    // EC-03: tenant legacy sso.enabled=false → flujo OID4VP sin 500
    //
    // El workflow cortocircuita en ssoEnabled=false antes de consultar BD o catálogo.
    // El request no produce 500 ni excepción no controlada.
    // =========================================================

    @Test
    void should_not_return_server_error_for_legacy_tenant_with_sso_disabled() throws Exception {
        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(new TenantSsoConfig(
                        TENANT, "domain", false,
                        new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                        List.of()
                )));

        mockMvc.perform(baseRequest()
                        .cookie(new Cookie(COOKIE_NAME, UUID.randomUUID().toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // ssoEnabled=false cortocircuita antes de acceder al repositorio o al catálogo.
        verify(sessionRepository, never()).findActiveById(any(SsoSessionId.class), anyString());
        verify(tenantSsoConfigPort, never()).resolveEligibleClients(anyString());
    }

    // =========================================================
    // HELPERS — request base
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
    // HELPERS — configuración y cliente
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of(CLIENT_ID)
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
    // Se bypasa la capa de dominio para crear estados que las invariantes
    // del agregado no permiten construir (e.g., expires_at en el pasado).
    // =========================================================

    /** Sesión ACTIVE con expires_at futuro y last_used_at hace 5 min. */
    private UUID insertActiveSession(String tenant, String holderHash) {
        UUID id = UUID.randomUUID();
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
        return id;
    }

    /**
     * Fila con state='ACTIVE' pero expires_at en el pasado.
     * El filtro SQL "AND expires_at > now()" la excluirá de findActiveById.
     */
    private UUID insertExpiredSession(String tenant, String holderHash) {
        UUID id = UUID.randomUUID();
        OffsetDateTime twoHoursAgo = OffsetDateTime.now(ZoneOffset.UTC).minusHours(2);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, tenant, holderHash,
                twoHoursAgo,
                twoHoursAgo.plusMinutes(30),   // expires_at = hace 90 min
                twoHoursAgo
        );
        return id;
    }
}
