package es.in2.vcverifier.sso.acceptance;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.config.TimeConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rnorth.ducttape.circuitbreakers.StateStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
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
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@Import(TimeConfig.class)
class LegacyConvivenciaIT {

    private static final String VP_TOKEN_B64 = Base64.getEncoder().encodeToString(
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig"
                    .getBytes(StandardCharsets.UTF_8));

    private static final String TENANT_SSO = "tenant-sso";
    private static final String TENANT_LEGACY = "tenant-legacy";

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
    @Autowired JdbcTemplate jdbcTemplate;

    @MockitoBean ClientRegistryProvider clientRegistryProvider;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean ClientLoaderConfig clientLoaderConfig;

    @MockitoBean SsoAuditPort auditPort;
    @MockitoBean TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean HashingService hashingService;
    @MockitoBean StateStore stateStore;
    @MockitoBean CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @MockitoBean AuthorizationResponseProcessorService authorizationResponseProcessorService;
    @Autowired SsoSessionRepositoryPort sessionRepositoryPort;

    @BeforeEach
    void clean() {
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS sso_session (
                 id TEXT PRIMARY KEY,
                 tenant TEXT NOT NULL,
                 holder_hash TEXT NOT NULL,
                 established_at TIMESTAMPTZ NOT NULL,
                 expires_at TIMESTAMPTZ NOT NULL,
                 last_used_at TIMESTAMPTZ NOT NULL,
                 state VARCHAR(32) NOT NULL
             )
        """);
        jdbcTemplate.execute("DELETE FROM sso_session");
        reset(auditPort);
        when(hashingService.sha256(any())).thenReturn("hashed-user");
        when(tenantSsoConfigPort.resolveTtl(anyString()))
                .thenReturn(SsoSessionTtl.systemDefault());
    }

    // ---- helpers -----------------------------------------------------------

    private static TenantSsoConfig enabledConfig(String tenant) {
        return new TenantSsoConfig(
                tenant,
                "example.com",
                true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofHours(1)),
                List.of()
        );
    }

    private static TenantSsoConfig legacyConfig(String tenant) {
        return new TenantSsoConfig(
                tenant,
                "",
                false,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofHours(1)),
                List.of()
        );
    }

    private void authResponse(String tenant, boolean expectCookie) throws Exception {
        var result = mockMvc.perform(post("/oid4vp/auth-response")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, tenant)
                        .param("state", "state-" + tenant + "-" + System.nanoTime())
                        .param("vp_token", VP_TOKEN_B64))
                // EUDISTACK-547: POST /oid4vp/auth-response = ACK 200 (redirect vía SSE), no 302.
                .andExpect(status().isOk());
        if (expectCookie) {
            result.andExpect(header().exists("Set-Cookie"));
        } else {
            result.andExpect(header().doesNotExist("Set-Cookie"));
        }
    }

    private int rows(String tenant) {
        return jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant=?", Integer.class, tenant);
    }

    // ---- tests -------------------------------------------------------------

    @Test
    @DisplayName("AC-01: tenant legacy completa OID4VP sin fila sso_session ni cookie SSO")
    void legacyTenant_completesWithoutSsoSessionOrCookie() throws Exception {
        // Given: a legacy tenant (sso.enabled=false)
        when(tenantSsoConfigPort.getByTenant(TENANT_LEGACY))
                .thenReturn(Optional.of(legacyConfig(TENANT_LEGACY)));

        // When: it completes an OID4VP authentication
        authResponse(TENANT_LEGACY, false);

        // Then: no sso_session row (and no SSO cookie, asserted in authResponse)
        assertThat(rows(TENANT_LEGACY)).isZero();
    }

    @Test
    @DisplayName("AC-02: SSO y legacy coexisten sin interferencia (independiente del orden)")
    void ssoAndLegacyTenants_coexistWithoutInterference() throws Exception {
        // Given: an SSO tenant (enabled) and a legacy tenant coexisting in the same IdP
        when(tenantSsoConfigPort.getByTenant(TENANT_SSO))
                .thenReturn(Optional.of(enabledConfig(TENANT_SSO)));
        when(tenantSsoConfigPort.getByTenant(TENANT_LEGACY))
                .thenReturn(Optional.of(legacyConfig(TENANT_LEGACY)));

        // When: both authenticate in legacy → SSO order (to prove order independence)
        authResponse(TENANT_LEGACY, false);
        authResponse(TENANT_SSO, true);

        // Then: the SSO tenant has its session; the legacy one does not. SSO activity creates no legacy rows.
        assertThat(rows(TENANT_SSO)).isEqualTo(1);
        assertThat(rows(TENANT_LEGACY)).isZero();

        // When: reverse order SSO → legacy
        authResponse(TENANT_SSO, true);
        authResponse(TENANT_LEGACY, false);

        // Then: the legacy tenant still has no row and the SSO one is unaffected
        assertThat(rows(TENANT_LEGACY)).isZero();
        assertThat(rows(TENANT_SSO)).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("EC-01: flip de flag en caliente — sólo crea sesión tras habilitar SSO")
    void flagFlip_createsSessionOnlyAfterEnable() throws Exception {
        // Given: the tenant initially operates as legacy (sso.enabled=false)
        when(tenantSsoConfigPort.getByTenant(TENANT_SSO))
                .thenReturn(Optional.of(legacyConfig(TENANT_SSO)));

        // When: it authenticates in the legacy phase
        authResponse(TENANT_SSO, false);

        // Then: no row
        assertThat(rows(TENANT_SSO)).isZero();

        // Given: hot config refresh → SSO enabled
        when(tenantSsoConfigPort.getByTenant(TENANT_SSO))
                .thenReturn(Optional.of(enabledConfig(TENANT_SSO)));

        // When: the request after the flip
        authResponse(TENANT_SSO, true);

        // Then: no retroactive creation — exactly 1 row (the one after the flip)
        assertThat(rows(TENANT_SSO)).isEqualTo(1);
    }

    @Test
    @DisplayName("ES-01: config del tenant ausente → fallback legacy sin error 500 ni sesión")
    void configAbsent_failsClosedWithoutError() throws Exception {
        // Given: a tenant with no config entry (getByTenant empty)
        when(tenantSsoConfigPort.getByTenant(TENANT_LEGACY))
                .thenReturn(Optional.empty());

        // When: it authenticates (fail-closed) — the legacy OID4VP flow completes with 200 and no cookie
        authResponse(TENANT_LEGACY, false);

        // Then: no 500 and no sso_session row
        assertThat(rows(TENANT_LEGACY)).isZero();
    }
}
