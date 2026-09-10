package es.in2.vcverifier.sso.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * B1 (review, EUD-149): the existing SSO ITs (e.g. {@code ReuseSsoSessionIT}) insert the
 * encrypted credential snapshot directly via JDBC — none of them exercise the real production
 * entry point, {@code POST /oid4vp/auth-response} -> {@code Oid4vpController.buildSsoAuthentication}
 * -> {@code SsoSessionAuthenticationSuccessHandler} -> {@code EstablishSsoSessionWorkflow}, so a
 * regression in that specific wiring (credentialJson never reaching the command) would go
 * undetected. This IT closes that gap end-to-end against a real Postgres (Testcontainers) and
 * the real {@link es.in2.vcverifier.sso.infrastructure.crypto.AesGcmSsoCredentialCipherAdapter}
 * (test key from {@code application-test.yaml}) — only VP/SD-JWT cryptographic verification
 * itself is mocked ({@link AuthorizationResponseProcessorService}, exactly like every other SSO
 * IT in this suite), since exercising real credential proof is a concern of
 * {@code AuthorizationResponseProcessorServiceImplTest}, not of this wiring.
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
class EstablishThenReuseRealLoginPathIT {

    private static final String TENANT       = "tenant-a";
    private static final String CLIENT_ID    = "clientA";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String COOKIE_NAME  = "__Secure-sso-" + TENANT;
    private static final String X_TENANT     = "X-Tenant";
    private static final String RAW_SUB      = "test-holder";

    // vp_token arrives Base64-encoded at the controller (mirrors what a real wallet sends).
    // Payload decodes to {"sub":"test-holder"} — Oid4vpController.extractSubFromVpToken() reads
    // it directly from the token, independently of the mocked credential claims below.
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
        registry.add("spring.datasource.url",      postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url",          postgres::getJdbcUrl);
        registry.add("spring.flyway.user",         postgres::getUsername);
        registry.add("spring.flyway.password",     postgres::getPassword);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private HashingService hashingService;

    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    // Spy, not a full mock: ReuseSsoSessionWorkflowImpl's ALLOWED path calls the REAL
    // issueCodeForReusedSession(...) on this same service to build the redirect Location — a
    // full mock would silently return null there and break the reuse half of this test. Only
    // handleAuthResponse (real VP/SD-JWT verification) is stubbed below.
    @MockitoSpyBean private AuthorizationResponseProcessorService authorizationResponseProcessorService;

    @BeforeEach
    void setUp() {
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

        // The only mocked step: real VP/SD-JWT verification is out of scope for this wiring
        // test — AuthorizationResponseProcessorServiceImplTest already covers that. Everything
        // downstream (Oid4vpController, SsoSessionAuthenticationSuccessHandler,
        // EstablishSsoSessionWorkflow, AesGcmSsoCredentialCipherAdapter, SsoSessionJdbcRepository)
        // is the real bean, against the real Testcontainers Postgres.
        JsonNode credentialJson = new ObjectMapper().createObjectNode()
                .put("sub", RAW_SUB)
                .put("vc_type", "LEARCredentialEmployee");
        org.mockito.Mockito.doReturn(credentialJson)
                .when(authorizationResponseProcessorService).handleAuthResponse(any(), any());
    }

    /**
     * B1 (review): real POST /oid4vp/auth-response must persist a NON-NULL encrypted
     * credential_snapshot — proving credentialJson actually reaches EstablishSsoSessionWorkflow
     * through the real production wiring, not just through a hand-built test principal.
     */
    @Test
    void establishViaRealHttpEndpoint_persistsNonNullEncryptedSnapshot() throws Exception {
        MvcResult result = mockMvc.perform(post("/oid4vp/auth-response")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("state", "establish-state-1")
                        .param("vp_token", VP_TOKEN_B64))
                // EUDISTACK-547: POST /oid4vp/auth-response is a 200 ACK (redirect via SSE), not a 3xx.
                .andExpect(status().isOk())
                .andExpect(cookie().exists(COOKIE_NAME))
                .andReturn();

        String sessionId = result.getResponse().getCookie(COOKIE_NAME).getValue();
        String expectedHolderHash = hashingService.sha256(RAW_SUB);

        byte[] snapshot = jdbcTemplate.queryForObject(
                "SELECT credential_snapshot FROM sso_session WHERE id = ? AND tenant = ? AND holder_hash = ?",
                byte[].class, sessionId, TENANT, expectedHolderHash);

        assertThat(snapshot).isNotNull();
        assertThat(snapshot.length).isGreaterThan(0);
    }

    /**
     * B1 (review) end-to-end: establish via the real HTTP entry point, THEN reuse via
     * {@code prompt=none} — the snapshot persisted by the first request must be decryptable and
     * actually let {@code ReuseSsoSessionWorkflowImpl} issue a code, proving the full production
     * path (not a JDBC-seeded fixture) supports silent SSO reuse across a "second application".
     */
    @Test
    void establishViaRealHttpEndpoint_thenReuseWithPromptNone_issuesCode() throws Exception {
        MvcResult establishResult = mockMvc.perform(post("/oid4vp/auth-response")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("state", "establish-state-2")
                        .param("vp_token", VP_TOKEN_B64))
                .andExpect(status().isOk())
                .andExpect(cookie().exists(COOKIE_NAME))
                .andReturn();

        String sessionId = establishResult.getResponse().getCookie(COOKIE_NAME).getValue();

        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "reuse-state-2")
                        .param("redirect_uri", REDIRECT_URI)
                        .cookie(new Cookie(COOKIE_NAME, sessionId))
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("code=")));
    }

    // =========================================================
    // HELPERS
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
                .build();
    }
}
