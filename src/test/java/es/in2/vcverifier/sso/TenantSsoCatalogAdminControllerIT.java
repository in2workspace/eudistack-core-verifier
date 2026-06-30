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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
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
import java.util.concurrent.ConcurrentHashMap;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * IT del catálogo SSO — endpoint de administración.
 *
 * Arquitectura de la prueba:
 *   - SsoCatalogRepositoryPort: implementación en memoria (InMemorySsoCatalogStore),
 *     reemplaza al adaptador JDBC/YAML real mediante @TestConfiguration @Primary.
 *   - tenantSsoConfigPort.resolveEligibleClients() se conecta al mismo store
 *     vía thenAnswer → AC-04 se prueba end-to-end: POST admin → decisión de reuse.
 *   - SsoSessionJdbcRepository: spy sobre PostgreSQL real (Testcontainers) para AC-04.
 *   - Seguridad: CSRF activo en /tenant/sso/eligible-clients (no está en lista
 *     de excepciones de CsrfProtectionMatcher); POST/DELETE llevan .with(csrf()).
 *
 * Escenarios cubiertos:
 *   AC-04  Alta refleja en siguiente decisión de reuse (end-to-end).
 *   AC-04  Baja refleja en siguiente decisión de reuse (interaction_required).
 *   EC-04  Alta duplicada idempotente: 200 + NO_OP en auditoría.
 *   ES-03  401 sin sesión admin activa.
 *   ES-03  403 cuando el tenant no está en el contexto (sin X-Tenant-Id).
 *   ES-03  Aislamiento cross-tenant: admin de A no afecta catálogo de B.
 *   NFR-O-01  Auditoría emitida en alta con campos correctos.
 *   NFR-O-01  Auditoría emitida en baja con campos correctos.
 */
@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import({TestClientConfig.class, TenantSsoCatalogAdminControllerIT.InMemoryCatalogConfig.class})
class TenantSsoCatalogAdminControllerIT {

    private static final String TENANT       = "tenant-a";
    private static final String TENANT_B     = "tenant-b";
    private static final String CLIENT_ID    = "clientA";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String COOKIE_NAME  = "__Secure-sso-" + TENANT;
    private static final String BASE_URL     = "/tenant/sso/eligible-clients";
    private static final String X_TENANT     = "X-Tenant";

    // =========================================================
    // ALMACÉN EN MEMORIA — compartido entre @TestConfiguration y @BeforeEach
    // =========================================================

    static final InMemorySsoCatalogStore CATALOG_STORE = new InMemorySsoCatalogStore();

    // =========================================================
    // TESTCONTAINERS — necesario para Flyway y SsoSessionJdbcRepository
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
    private ClientLoaderConfig clientLoaderConfig;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private DcqlProfileResolver dcqlProfileResolver;

    @MockitoBean
    private CustomErrorResponseHandler customErrorResponseHandler;

    @MockitoBean
    private ClientRegistryProvider clientRegistryProvider;

    @MockitoSpyBean
    private SsoSessionJdbcRepository sessionRepository;

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

        CATALOG_STORE.clear();
        reset(auditPort);

        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(defaultConfig()));
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(1), Duration.ofMinutes(10)));

        // Conecta resolveEligibleClients() al almacén en memoria: cuando el admin
        // añade/elimina un cliente via POST/DELETE, la siguiente decisión de reuse
        // refleja el cambio sin necesidad de recargar configuración YAML.
        when(tenantSsoConfigPort.resolveEligibleClients(anyString())).thenAnswer(inv -> {
            String tenant = inv.getArgument(0);
            List<String> ids = CATALOG_STORE.listClients(tenant).stream()
                    .map(SsoEligibleClient::clientId)
                    .toList();
            return TenantSsoCatalog.of(ids);
        });

        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildClient());
    }

    // =========================================================
    // AC-04: Alta refleja en la siguiente decisión de reuse
    //
    // Flujo: POST /tenant/sso/eligible-clients → cliente en almacén →
    // GET /oidc/authorize prompt=none → resolveEligibleClients() lee el almacén →
    // TenantSsoPolicy devuelve Allowed → redirect sin error.
    // =========================================================

    @Test
    void should_allow_reuse_after_admin_adds_client_to_catalog() throws Exception {
        UUID sessionId = insertActiveSession(TENANT, "holder-ac04-add");

        // Admin añade clientA al catálogo del tenant.
        mockMvc.perform(post(BASE_URL)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"" + CLIENT_ID + "\"}"))
                .andExpect(status().isOk());

        // Siguiente decisión: el catálogo ya tiene al cliente → reuse concedido.
        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", REDIRECT_URI)
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("error="))));
    }

    // =========================================================
    // AC-04: Baja refleja en la siguiente decisión de reuse
    //
    // El cliente se elimina del catálogo → siguiente reuse devuelve
    // interaction_required (REJECT_CATALOG).
    // =========================================================

    @Test
    void should_deny_reuse_after_admin_removes_client_from_catalog() throws Exception {
        // El cliente ya está en el catálogo antes del test.
        CATALOG_STORE.addIfAbsent(TENANT, SsoEligibleClient.of(CLIENT_ID));
        UUID sessionId = insertActiveSession(TENANT, "holder-ac04-rem");

        // Admin elimina el cliente.
        mockMvc.perform(delete(BASE_URL + "/" + CLIENT_ID)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT))
                .andExpect(status().isNoContent());

        // Siguiente decisión: catálogo vacío → interaction_required.
        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", REDIRECT_URI)
                        .cookie(new Cookie(COOKIE_NAME, sessionId.toString()))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("error=interaction_required")));
    }

    // =========================================================
    // EC-04: Alta duplicada idempotente
    //
    // Dos POST con el mismo client_id → 200 ambos, catálogo con una sola entrada.
    // El segundo POST emite SSO_CATALOG_NO_OP + ALREADY_EXISTS.
    // =========================================================

    @Test
    void should_be_idempotent_on_duplicate_add() throws Exception {
        String firstAdd  = "{\"client_id\":\"dup-client\"}";

        mockMvc.perform(post(BASE_URL)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(firstAdd))
                .andExpect(status().isOk());

        mockMvc.perform(post(BASE_URL)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(firstAdd))
                .andExpect(status().isOk());

        // Un solo elemento en el catálogo.
        mockMvc.perform(get(BASE_URL)
                        .with(user("admin"))
                        .header(X_TENANT, TENANT))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eligible_clients", hasSize(1)))
                .andExpect(jsonPath("$.eligible_clients[0]").value("dup-client"));

        // El segundo POST emite NO_OP con outcome=ALREADY_EXISTS.
        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_NO_OP
                && "ALREADY_EXISTS".equals(event.getOutcome())));
    }

    // =========================================================
    // ES-03: 401 sin sesión admin
    // =========================================================

    @Test
    void should_return_401_when_no_admin_session() throws Exception {
        mockMvc.perform(get(BASE_URL)
                        .header(X_TENANT, TENANT))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // ES-03: 403 cuando el tenant no está en el contexto
    //
    // TenantDomainFilter no resuelve tenant (sin X-Tenant-Id ni hostname con punto)
    // → el controlador devuelve 403 FORBIDDEN.
    // =========================================================

    @Test
    void should_return_403_when_tenant_not_in_context() throws Exception {
        mockMvc.perform(get(BASE_URL)
                        .with(user("admin")))
                // Sin X-Tenant-Id, servidor "localhost" sin punto → tenant null → 403.
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // ES-03: Aislamiento cross-tenant
    //
    // El admin de tenant-a gestiona sólo su propio catálogo.
    // El catálogo de tenant-b permanece vacío.
    // =========================================================

    @Test
    void should_not_affect_tenant_b_catalog_when_managing_tenant_a() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"exclusive-client\"}"))
                .andExpect(status().isOk());

        // El catálogo de tenant-b no se ha modificado.
        mockMvc.perform(get(BASE_URL)
                        .with(user("admin"))
                        .header(X_TENANT, TENANT_B))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eligible_clients").isEmpty());
    }

    // =========================================================
    // NFR-O-01: Auditoría en alta
    //
    // POST → auditPort.publish() con eventType=SSO_CATALOG_CLIENT_ADDED,
    // tenant, clientId y outcome=ADDED correctos.
    // =========================================================

    @Test
    void should_emit_audit_event_with_correct_fields_on_add() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"audited-client\"}"))
                .andExpect(status().isOk());

        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                && TENANT.equals(event.getTenant())
                && "audited-client".equals(event.getClientId())
                && "ADDED".equals(event.getOutcome())));
    }

    // =========================================================
    // NFR-O-01: Auditoría en baja
    //
    // DELETE → auditPort.publish() con eventType=SSO_CATALOG_CLIENT_REMOVED,
    // tenant, clientId y outcome=REMOVED correctos.
    // =========================================================

    @Test
    void should_emit_audit_event_with_correct_fields_on_remove() throws Exception {
        CATALOG_STORE.addIfAbsent(TENANT, SsoEligibleClient.of("remove-target"));

        mockMvc.perform(delete(BASE_URL + "/remove-target")
                        .with(user("admin"))
                        .with(csrf())
                        .header(X_TENANT, TENANT))
                .andExpect(status().isNoContent());

        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED
                && TENANT.equals(event.getTenant())
                && "remove-target".equals(event.getClientId())
                && "REMOVED".equals(event.getOutcome())));
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
    // HELPERS — inserción directa en BD (para AC-04)
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

    // =========================================================
    // @TestConfiguration — SsoCatalogRepositoryPort en memoria
    //
    // Reemplaza al adaptador JDBC/YAML real. El mismo store estático
    // es accesible desde @BeforeEach para resetear el estado entre tests.
    // =========================================================

    @TestConfiguration
    static class InMemoryCatalogConfig {

        @Bean
        @Primary
        SsoCatalogRepositoryPort ssoCatalogRepositoryPort() {
            return CATALOG_STORE;
        }
    }

    // =========================================================
    // IMPLEMENTACIÓN EN MEMORIA DE SsoCatalogRepositoryPort
    // =========================================================

    static class InMemorySsoCatalogStore implements SsoCatalogRepositoryPort {

        private final ConcurrentHashMap<String, Set<SsoEligibleClient>> store =
                new ConcurrentHashMap<>();

        void clear() {
            store.clear();
        }

        @Override
        public List<SsoEligibleClient> listClients(String tenant) {
            return store.getOrDefault(tenant, Set.of()).stream().toList();
        }

        @Override
        public boolean addIfAbsent(String tenant, SsoEligibleClient client) {
            return store.computeIfAbsent(tenant, k -> ConcurrentHashMap.newKeySet())
                    .add(client);
        }

        @Override
        public boolean removeIfPresent(String tenant, SsoEligibleClient client) {
            Set<SsoEligibleClient> set = store.get(tenant);
            return set != null && set.remove(client);
        }
    }
}
