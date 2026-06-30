package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.config.TimeConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.rnorth.ducttape.circuitbreakers.StateStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@Import(TimeConfig.class)
class EstablishSsoSessionIT {

    // vp_token arrives Base64-encoded at the controller (mirrors what a real wallet sends)
    private static final String VP_TOKEN_B64 = Base64.getEncoder().encodeToString(
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig"
                    .getBytes(StandardCharsets.UTF_8));

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

    @Autowired MockMvc mockMvc;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @MockitoBean
    ClientRegistryProvider clientRegistryProvider;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean
    ClientLoaderConfig clientLoaderConfig;
    @Autowired
    SsoSessionAuthenticationSuccessHandler handler;

    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private HashingService hashingService;
    // Clock eliminado: @Import(TimeConfig.class) ya provee un Clock real.
    // Un mock sin stubbear provoca NPE en Instant.now(clock).
    @MockitoBean
    StateStore stateStore;
    @MockitoBean
    CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @MockitoBean
    EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    @MockitoBean
    AuthorizationResponseProcessorService authorizationResponseProcessorService;
    @MockitoBean
    SsoCatalogRepositoryPort ssoCatalogRepositoryPort;


    @BeforeEach
    void clean() {
        reset(auditPort);

        jdbcTemplate.execute("""
        CREATE TABLE IF NOT EXISTS sso_session (
            id SERIAL PRIMARY KEY,
            tenant VARCHAR(255),
            state VARCHAR(50)
        )
    """);
    }

    // =========================================================
    // AC-01 + AC-03: happy path
    // =========================================================
    @Test
    void establishSession_createsRow_and_setsCookie() throws Exception {

        // -------------------------
        // CONFIG
        // -------------------------
        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(Boolean.TRUE);

        when(tenantSsoConfigPort.getByTenant("tenant-a"))
                .thenReturn(Optional.of(config));

        // -------------------------
        // WORKFLOW MOCK
        // -------------------------
        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor descriptor =
                mock(EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor.class);

        when(descriptor.value()).thenReturn("mock-session");
        when(descriptor.expiresAt())
                .thenReturn(Instant.now().plusSeconds(60));

        when(establishSsoSessionWorkflow.execute(any()))
                .thenReturn(descriptor);

        // -------------------------
        // CACHE
        // -------------------------
        OAuth2AuthorizationRequest request =
                OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("http://test")
                        .clientId("client-id")
                        .redirectUri("http://redirect")
                        .state("test-state")
                        .additionalParameters(Map.of(
                                "expiration", Instant.now().plusSeconds(60).getEpochSecond(),
                                "nonce", "nonce"
                        ))
                        .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get("test-state"))
                .thenReturn(request);

        // -------------------------
        // AUTH SERVICE
        // -------------------------
        doNothing().when(authorizationResponseProcessorService)
                .handleAuthResponse(anyString(), anyString());

        // -------------------------
        // PRINCIPAL
        // -------------------------
        Map<String, Object> principal = new HashMap<>();
        principal.put("tenant", "tenant-a");
        principal.put("holderHash", "hash");
        principal.put("clientId", "client-id");
        principal.put("tenantSlug", "tenant-a");

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        "user",
                        null,
                        List.of(() -> "ROLE_USER")
                );

        auth.setDetails(principal);

        // -------------------------
        // CALL
        // -------------------------
        mockMvc.perform(post("/oid4vp/auth-response")
                        // TENANT_ATTRIBUTE necesario: buildSsoAuthentication() usa TenantDomainFilter.getCurrentTenant()
                        // para construir el tenantSlug de la cookie. Sin él, la cookie queda como "__Secure-sso-".
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, "tenant-a")
                        .principal(auth)
                        .param("state", "test-state")
                        .param("vp_token", VP_TOKEN_B64)
                        .contentType("application/json")
                        .content("""
                {
                  "vp": "dummy-vp-token",
                  "tenant": "tenant-a"
                }
                """))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(cookie().exists("__Secure-sso-tenant-a"));

        verify(establishSsoSessionWorkflow).execute(any());
    }

    // =========================================================
    // AC-04: tenant legacy sso.enabled=false => no cookie, OID4VP redirect intacto
    // =========================================================
    @Test
    void legacyTenant_doesNotSetCookie() throws Exception {

        // SsoConfigInconsistentException es capturada en el handler sin re-lanzarse,
        // por lo que el flujo OID4VP completa con redirect (sin cookie SSO).
        when(establishSsoSessionWorkflow.execute(any()))
                .thenThrow(new SsoConfigInconsistentException("invalid config"));

        mockMvc.perform(post("/oid4vp/auth-response")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, "legacy-tenant")
                        .principal(() -> "legacy-tenant")
                        .param("state", "test-state")
                        .param("vp_token", VP_TOKEN_B64))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().doesNotExist("Set-Cookie"));

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='legacy-tenant'",
                Integer.class
        );

        assertThat(count).isEqualTo(0);
    }

    // =========================================================
    // ES-01: VP inválida -> no session + access_denied + sso_establish_failed
    // =========================================================
    @Test
    void invalidVp_returnsAccessDenied_and_noSession() throws Exception {

        // -------------------------
        // MOCK SERVICE FAILURE
        // -------------------------
        doThrow(new SsoConfigInconsistentException("invalid vp"))
                .when(authorizationResponseProcessorService)
                .handleAuthResponse(anyString(), anyString());

        // -------------------------
        // CALL
        // -------------------------
        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "tenant-a")
                        .param("state", "test-state")
                        .param("vp_token", VP_TOKEN_B64))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("access_denied"))
                .andExpect(jsonPath("$.detail").value("sso_establish_failed"));

        // -------------------------
        // DB ASSERT
        // -------------------------
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(count).isEqualTo(0);

        // -------------------------
        // AUDIT VERIFY
        // -------------------------
        verify(auditPort, atLeastOnce())
                .publish(argThat(e -> e instanceof SsoAuditEvent));
    }
}