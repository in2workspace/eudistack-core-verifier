package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * IT — TenantSsoCatalogAdminController (Spring Boot + MockMvc).
 *
 * AC-04  Alta/baja del catálogo SSO se delegan al repositorio y emiten auditoría.
 * EC-04  Alta duplicada idempotente: dos POST del mismo client_id → 201 en ambos.
 * ES-03  401 sin sesión admin: request sin autenticación es rechazada.
 * ES-03  403 cross-tenant: admin del tenant A no puede modificar el catálogo del tenant B.
 * NFR-O-01  Eventos de auditoría SSO_CATALOG_CLIENT_ADDED / SSO_CATALOG_CLIENT_REMOVED emitidos.
 */
@SpringBootTest(properties = {
        "spring.flyway.enabled=false",
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TenantSsoCatalogAdminControllerIT {

    private static final String TENANT       = "tenant-a";
    private static final String TENANT_B     = "tenant-b";
    private static final String CLIENT_ID    = "clientA";
    private static final String X_TENANT     = "X-Tenant";
    private static final String BASE_URL     = "/tenant/sso/eligible-clients";

    // =========================================================
    // SPRING BEANS
    // =========================================================

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    @MockitoBean
    private SsoAuditPort auditPort;

    @MockitoBean
    private TenantSsoConfigPort tenantSsoConfigPort;

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
        reset(auditPort, ssoCatalogRepositoryPort);

        when(ssoCatalogRepositoryPort.addClient(anyString(), any(SsoEligibleClient.class)))
                .thenReturn(true);
        when(ssoCatalogRepositoryPort.removeClient(anyString(), any(SsoEligibleClient.class)))
                .thenReturn(true);
        when(tenantSsoConfigPort.getByTenant(anyString()))
                .thenReturn(Optional.of(defaultConfig()));
    }

    // =========================================================
    // AC-04 ALTA: POST delega en repositorio y emite auditoría
    // Verifica que POST /tenant/sso/eligible-clients → 201 Created,
    // catalogRepository.addClient invocado con los parámetros correctos
    // y SSO_CATALOG_CLIENT_ADDED publicado por auditPort.
    // =========================================================
    @Test
    void should_return201_and_delegateToRepository_onAdd() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\": \"" + CLIENT_ID + "\"}")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isCreated());

        verify(ssoCatalogRepositoryPort, times(1))
                .addClient(eq(TENANT), eq(SsoEligibleClient.of(CLIENT_ID)));

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                        && TENANT.equals(event.getTenant())
                        && CLIENT_ID.equals(event.getClientId())));
    }

    // =========================================================
    // AC-04 BAJA: DELETE delega en repositorio y emite auditoría
    // Verifica que DELETE /tenant/sso/eligible-clients/{clientId} → 204 No Content,
    // catalogRepository.removeClient invocado y SSO_CATALOG_CLIENT_REMOVED publicado.
    // =========================================================
    @Test
    void should_return204_and_delegateToRepository_onRemove() throws Exception {
        mockMvc.perform(delete(BASE_URL + "/" + CLIENT_ID)
                        .header(X_TENANT, TENANT)
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNoContent());

        verify(ssoCatalogRepositoryPort, times(1))
                .removeClient(eq(TENANT), eq(SsoEligibleClient.of(CLIENT_ID)));

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED
                        && TENANT.equals(event.getTenant())
                        && CLIENT_ID.equals(event.getClientId())));
    }

    // =========================================================
    // EC-04 ALTA DUPLICADA IDEMPOTENTE
    // Dos POST del mismo client_id → 201 en ambos casos.
    // La primera llamada devuelve true (ADDED), la segunda false (ALREADY_PRESENT).
    // Ambas emiten un evento de auditoría; la segunda con outcome ALREADY_PRESENT.
    // =========================================================
    @Test
    void should_return201_onBothPosts_whenClientAlreadyExists() throws Exception {
        // Segunda llamada: cliente ya presente → addClient devuelve false
        when(ssoCatalogRepositoryPort.addClient(eq(TENANT), eq(SsoEligibleClient.of(CLIENT_ID))))
                .thenReturn(true)
                .thenReturn(false);

        String body = "{\"client_id\": \"" + CLIENT_ID + "\"}";

        // Primera alta → ADDED
        mockMvc.perform(post(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isCreated());

        // Alta duplicada → sigue siendo 201 (idempotente, no 409)
        mockMvc.perform(post(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isCreated());

        // El repositorio fue llamado dos veces con los mismos parámetros
        verify(ssoCatalogRepositoryPort, times(2))
                .addClient(eq(TENANT), eq(SsoEligibleClient.of(CLIENT_ID)));

        // Auditoría emitida en ambas invocaciones
        verify(auditPort, times(2)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED));

        // La segunda auditoría refleja ALREADY_PRESENT
        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                        && "ALREADY_PRESENT".equals(event.getOutcome())));
    }

    // =========================================================
    // ES-03 / AD-3: 401 sin sesión admin
    // Request GET sin autenticación → Spring Security rechaza (4xx).
    // El endpoint /tenant/sso/eligible-clients está bajo anyRequest().authenticated().
    // =========================================================
    @Test
    void should_return4xx_whenRequestIsUnauthenticated() throws Exception {
        mockMvc.perform(get(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().is4xxClientError());
    }

    // =========================================================
    // ES-03 / NFR-S-02: 403 cross-tenant
    // Admin autenticado con tenant-a como contexto intenta operar sobre tenant-b.
    // El controlador detecta la discrepancia y devuelve 403 Forbidden.
    // =========================================================
    @Test
    void should_return403_whenAuthTenantDiffersFromRequestTenant() throws Exception {
        // Authentication cuyo principal lleva tenant=tenant-a
        UsernamePasswordAuthenticationToken tenantAAuth =
                new UsernamePasswordAuthenticationToken(
                        Map.of("tenant", TENANT),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                );

        // Request para tenant-b → controller detecta cross-tenant y devuelve 403
        mockMvc.perform(get(BASE_URL)
                        .header(X_TENANT, TENANT_B)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(tenantAAuth))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // ES-03 / NFR-S-02: 403 cross-tenant en operación de escritura
    // Admin de tenant-a intenta añadir un cliente al catálogo de tenant-b.
    // =========================================================
    @Test
    void should_return403_onPost_whenAuthTenantDiffersFromRequestTenant() throws Exception {
        UsernamePasswordAuthenticationToken tenantAAuth =
                new UsernamePasswordAuthenticationToken(
                        Map.of("tenant", TENANT),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                );

        mockMvc.perform(post(BASE_URL)
                        .header(X_TENANT, TENANT_B)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\": \"" + CLIENT_ID + "\"}")
                        .with(authentication(tenantAAuth))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        // El repositorio no debe ser invocado si el tenant es cross-tenant
        verify(ssoCatalogRepositoryPort, never()).addClient(anyString(), any());
    }

    // =========================================================
    // NFR-O-01: auditoría SSO_CATALOG_CLIENT_ADDED en alta exitosa
    // Campos tenant y clientId presentes en el evento; outcome = ADDED.
    // =========================================================
    @Test
    void should_emitCatalogAddedAuditEvent_withCorrectFields() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\": \"" + CLIENT_ID + "\"}")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isCreated());

        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED
                        && TENANT.equals(event.getTenant())
                        && CLIENT_ID.equals(event.getClientId())
                        && "ADDED".equals(event.getOutcome())));
    }

    // =========================================================
    // NFR-O-01: auditoría SSO_CATALOG_CLIENT_REMOVED en baja exitosa
    // Campos tenant y clientId presentes en el evento; outcome = REMOVED.
    // =========================================================
    @Test
    void should_emitCatalogRemovedAuditEvent_withCorrectFields() throws Exception {
        mockMvc.perform(delete(BASE_URL + "/" + CLIENT_ID)
                        .header(X_TENANT, TENANT)
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNoContent());

        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED
                        && TENANT.equals(event.getTenant())
                        && CLIENT_ID.equals(event.getClientId())
                        && "REMOVED".equals(event.getOutcome())));
    }

    // =========================================================
    // GET lista el catálogo del tenant desde el config port
    // =========================================================
    @Test
    void should_returnEligibleClients_onGet() throws Exception {
        // El CsrfProtectionMatcher custom aplica CSRF a TODAS las rutas no excluidas, incluyendo GET
        mockMvc.perform(get(BASE_URL)
                        .header(X_TENANT, TENANT)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eligible_clients").isArray())
                .andExpect(jsonPath("$.eligible_clients[0]").value(CLIENT_ID));
    }

    // =========================================================
    // HELPERS — configuración por defecto
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                TENANT, "domain", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(5)),
                List.of(CLIENT_ID)
        );
    }
}
