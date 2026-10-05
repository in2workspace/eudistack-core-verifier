package es.in2.vcverifier.sso.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.vcverifier.shared.domain.util.Constants.BROWSER_BINDING_HASH;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * EUD-252: SSO multi-application with the wallet on ANOTHER device.
 *
 * <p>Drives the real production path end to end — /oidc/authorize (real converter + error
 * handler), POST /oid4vp/auth-response (real controller, real code issuance), the SSE hand-off and
 * GET /api/login/complete (real workflow + establishment against Testcontainers Postgres). Only VP
 * cryptographic verification is stubbed: the stub reads the REAL cached authorization request and
 * issues a REAL code, so binding hash, PKCE and code invalidation are all genuine.
 *
 * <p>"Browser" and "wallet" are modelled by which cookies each request carries: the wallet POST
 * carries none; the browser's requests carry what the browser received.
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
class CrossDeviceSsoLoginIT {

    private static final String TENANT        = "tenant-a";
    private static final String CLIENT_ID     = "clientA";
    private static final String REDIRECT_URI  = "https://localhost/callback";
    private static final String SSO_COOKIE    = "__Secure-sso-" + TENANT;
    private static final String TX_COOKIE     = "__Host-sso-tx";
    private static final String X_TENANT      = "X-Tenant";
    private static final String RAW_SUB       = "test-holder";
    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Payload {"sub":"test-holder"} — Oid4vpController.extractSubFromVpToken() reads it from the token.
    private static final String VP_TOKEN_B64 = Base64.getEncoder().encodeToString(
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig".getBytes(StandardCharsets.UTF_8));

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

    /** Code issued per login state by the VP stub — what an attacker would try to redeem. */
    private final Map<String, String> issuedCodes = new ConcurrentHashMap<>();

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @Autowired private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    @Autowired private OAuth2AuthorizationService oAuth2AuthorizationService;

    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    @MockitoSpyBean private SseEmitterStore sseEmitterStore;
    @MockitoSpyBean private AuthorizationResponseProcessorService authorizationResponseProcessorService;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("DELETE FROM sso_session");
        reset(auditPort);
        clearInvocations(sseEmitterStore);

        when(tenantSsoConfigPort.getByTenant(anyString())).thenReturn(Optional.of(config(true)));
        when(tenantSsoConfigPort.resolveTtl(anyString())).thenReturn(SsoSessionTtl.systemDefault());
        when(tenantSsoConfigPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of(CLIENT_ID))));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(new DcqlQuery(List.of()));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(buildClient());

        // Only VP crypto is stubbed. The answer consumes the REAL cached authorization request (as
        // the real implementation does) and issues a REAL code through the real issuance path.
        JsonNode credentialJson = new ObjectMapper().createObjectNode()
                .put("sub", RAW_SUB)
                .put("vc_type", "LEARCredentialEmployee");
        doAnswer(invocation -> {
            String state = invocation.getArgument(0);
            OAuth2AuthorizationRequest cached = cacheStoreForOAuth2AuthorizationRequest.get(state);
            cacheStoreForOAuth2AuthorizationRequest.delete(state);
            var addl = cached.getAdditionalParameters();
            String redirectUrl = authorizationResponseProcessorService.issueCodeForReusedSession(
                    cached.getClientId(), cached.getRedirectUri(), cached.getScopes(), state,
                    (String) addl.get(PkceParameterNames.CODE_CHALLENGE),
                    (String) addl.get(PkceParameterNames.CODE_CHALLENGE_METHOD),
                    null, credentialJson);
            String code = codeFrom(redirectUrl);
            issuedCodes.put(state, code);
            return new AuthResponseResult(credentialJson, redirectUrl, cached.getRedirectUri(), state,
                    cached.getClientId(), code, (String) addl.get(BROWSER_BINDING_HASH), cached.getAuthorizationUri());
        }).when(authorizationResponseProcessorService).handleAuthResponse(anyString(), anyString(), any());
    }

    // =========================================================
    // Happy path: wallet on another device
    // =========================================================

    @Test
    void crossDevice_browserClosesLogin_getsSsoCookieAndCode_thenSilentReuseWorks() throws Exception {
        // Given: the browser starts the login and is bound with __Host-sso-tx
        String state = "xd-ok-" + UUID.randomUUID();
        Cookie txCookie = authorizeInBrowser(state);

        // When: the wallet (another device, no browser cookies) posts the VP
        MvcResult walletResult = walletPost(state);

        // Then: the wallet gets a bare 200 — no SSO cookie lands on the wallet's device
        assertThat(walletResult.getResponse().getHeaders("Set-Cookie")).isEmpty();
        // ... and the browser receives over SSE the one-time close URL, not the code
        String closeUrl = sseUrlFor(state);
        assertThat(closeUrl).contains("/api/login/complete?h=").doesNotContain("code=");

        // When: the browser follows it with its binding cookie
        MvcResult closeResult = browserClose(closeUrl, txCookie)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?code=")))
                .andExpect(header().string("Location", containsString("state=" + state)))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(cookie().exists(SSO_COOKIE))
                .andReturn();

        // Then: the delivered code is genuine and still redeemable
        String code = codeFrom(closeResult.getResponse().getHeader("Location"));
        assertThat(cacheStoreForAuthorizationCodeData.getIfPresent(code)).isNotNull();
        assertThat(oAuth2AuthorizationService.findByToken(code, new OAuth2TokenType(OAuth2ParameterNames.CODE)))
                .isNotNull();

        // When: a second application in the SAME browser asks silently
        String sessionId = closeResult.getResponse().getCookie(SSO_COOKIE).getValue();
        mockMvc.perform(get("/oidc/authorize")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid")
                        .param("state", "reuse-" + state)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("prompt", "none")
                        .cookie(new Cookie(SSO_COOKIE, sessionId)))
                // Then: code without QR
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("code=")))
                .andExpect(header().string("Location", containsString("state=reuse-" + state)));
    }

    @Test
    void crossDevice_closeHandleIsSingleUse() throws Exception {
        // Given: a login closed once by its browser
        String state = "xd-once-" + UUID.randomUUID();
        Cookie txCookie = authorizeInBrowser(state);
        walletPost(state);
        String closeUrl = sseUrlFor(state);
        browserClose(closeUrl, txCookie).andExpect(status().is3xxRedirection());

        // When / Then: replaying the same URL is rejected without any redirect
        browserClose(closeUrl, txCookie)
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(cookie().doesNotExist(SSO_COOKIE));
    }

    @Test
    void crossDevice_unknownHandle_returns400() throws Exception {
        mockMvc.perform(get("/api/login/complete")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("h", "never-issued"))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    // =========================================================
    // Hijack attempts: someone who learnt the public state
    // =========================================================

    @Test
    void hijack_closeWithoutBindingCookie_accessDeniedAndCodeInvalidated() throws Exception {
        assertHijackRejected(null, "browser_binding_missing");
    }

    @Test
    void hijack_closeWithAnotherBrowsersBindingCookie_accessDeniedAndCodeInvalidated() throws Exception {
        assertHijackRejected(new Cookie(TX_COOKIE, "attackerBrowserValueXXXXXXXXXXXXXXXXXXXXXXX"),
                "browser_binding_mismatch");
    }

    private void assertHijackRejected(Cookie attackerCookie, String expectedReason) throws Exception {
        // Given: the victim's browser starts the login and the wallet presents
        String state = "xd-hijack-" + UUID.randomUUID();
        authorizeInBrowser(state);
        walletPost(state);
        String closeUrl = sseUrlFor(state);
        String issuedCode = issuedCodes.get(state);

        // When: an attacker's browser (subscribed to the public SSE state) follows the close URL
        browserClose(closeUrl, attackerCookie)
                // Then: OAuth error back to the registered redirect_uri, no code, no SSO cookie
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location",
                        REDIRECT_URI + "?error=access_denied&state=" + state))
                .andExpect(cookie().doesNotExist(SSO_COOKIE));

        // ... the code is invalidated: gone from both stores read by the token endpoint
        assertThat(cacheStoreForAuthorizationCodeData.getIfPresent(issuedCode)).isNull();
        assertThat(oAuth2AuthorizationService.findByToken(issuedCode, new OAuth2TokenType(OAuth2ParameterNames.CODE)))
                .isNull();
        // ... and it cannot be redeemed
        mockMvc.perform(post("/oidc/token")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("grant_type", "authorization_code")
                        .param("code", issuedCode)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(200));
        // ... no session was persisted, and the rejection is audited
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sso_session WHERE tenant = ?",
                Integer.class, TENANT)).isZero();
        verify(auditPort, atLeastOnce()).publish(argThat((SsoAuditEvent e) ->
                e.getEventType() == SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED
                        && expectedReason.equals(e.getReason())));
    }

    // =========================================================
    // F1: a state already in flight can't be taken over
    // =========================================================

    @Test
    void duplicateStateFromAnotherBrowser_isRejected_andVictimLoginStillCompletes() throws Exception {
        // Given: the victim's browser starts the login
        String state = "xd-dup-" + UUID.randomUUID();
        Cookie victimTx = authorizeInBrowser(state);
        OAuth2AuthorizationRequest original = cacheStoreForOAuth2AuthorizationRequest.get(state);

        // When: an attacker's browser (no victim cookie) replays /authorize with the same state
        MvcResult attacker = mockMvc.perform(authorizeRequest(state))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Then: verifier error page, not the login page; the in-flight login is untouched
        assertThat(attacker.getResponse().getHeader("Location")).contains("/error?").doesNotContain("/login?");
        OAuth2AuthorizationRequest after = cacheStoreForOAuth2AuthorizationRequest.get(state);
        assertThat(after).isSameAs(original);
        assertThat(after.getAdditionalParameters().get(BROWSER_BINDING_HASH))
                .isEqualTo(original.getAdditionalParameters().get(BROWSER_BINDING_HASH));
        assertThat(after.getAdditionalParameters().get(VP_NONCE))
                .isEqualTo(original.getAdditionalParameters().get(VP_NONCE));

        // ... and the victim's login completes normally in the victim's browser
        walletPost(state);
        browserClose(sseUrlFor(state), victimTx)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?code=")))
                .andExpect(cookie().exists(SSO_COOKIE));
    }

    @Test
    void duplicateStateFromSameBrowser_isAcceptedAsRetry() throws Exception {
        // Given
        String state = "xd-retry-" + UUID.randomUUID();
        Cookie tx = authorizeInBrowser(state);
        Object originalNonce = cacheStoreForOAuth2AuthorizationRequest.get(state).getAdditionalParameters().get(VP_NONCE);

        // When: the same browser (same __Host-sso-tx) retries /authorize
        MvcResult retry = mockMvc.perform(authorizeRequest(state).cookie(tx))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login?")))
                .andReturn();

        // Then: same binding value re-emitted, new request (and nonce) replaced the old one
        assertThat(retry.getResponse().getCookie(TX_COOKIE).getValue()).isEqualTo(tx.getValue());
        assertThat(cacheStoreForOAuth2AuthorizationRequest.get(state).getAdditionalParameters().get(VP_NONCE))
                .isNotEqualTo(originalNonce);
        walletPost(state);
        browserClose(sseUrlFor(state), tx)
                .andExpect(status().is3xxRedirection())
                .andExpect(cookie().exists(SSO_COOKIE));
    }

    @Test
    void duplicateStateOnSsoDisabledTenant_isRejected() throws Exception {
        // Given
        when(tenantSsoConfigPort.getByTenant(anyString())).thenReturn(Optional.of(config(false)));
        String state = "legacy-dup-" + UUID.randomUUID();
        mockMvc.perform(authorizeRequest(state))
                .andExpect(header().string("Location", containsString("/login?")));

        // When / Then: no binding to prove "same browser" → any duplicate is rejected
        mockMvc.perform(authorizeRequest(state))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/error?")));
    }

    // =========================================================
    // W2: a bound login never gets the code over SSE
    // =========================================================

    @Test
    void boundLoginWithoutUsableSubject_stillClosesInBrowser_codeWithoutSsoSession() throws Exception {
        // Given: a VP whose token has neither sub nor iss
        String state = "xd-nosub-" + UUID.randomUUID();
        Cookie tx = authorizeInBrowser(state);
        String vpNoSub = Base64.getEncoder().encodeToString(
                "eyJhbGciOiJub25lIn0.e30.fakesig".getBytes(StandardCharsets.UTF_8));

        // When
        mockMvc.perform(post("/oid4vp/auth-response")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("state", state)
                        .param("vp_token", vpNoSub))
                .andExpect(status().isOk());

        // Then: the SSE still carries the close URL, never the code
        String closeUrl = sseUrlFor(state);
        assertThat(closeUrl).contains("/api/login/complete?h=").doesNotContain("code=");
        // ... and the bound browser gets the code, without an SSO session
        browserClose(closeUrl, tx)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?code=")))
                .andExpect(cookie().doesNotExist(SSO_COOKIE));
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sso_session WHERE tenant = ?",
                Integer.class, TENANT)).isZero();
    }

    // =========================================================
    // EC-07: SSO-disabled tenant keeps the legacy flow
    // =========================================================

    @Test
    void ssoDisabledTenant_noBindingCookie_andSseCarriesRpRedirectDirectly() throws Exception {
        // Given
        when(tenantSsoConfigPort.getByTenant(anyString())).thenReturn(Optional.of(config(false)));
        String state = "legacy-" + UUID.randomUUID();

        // When: the browser starts the login
        MvcResult authorize = mockMvc.perform(authorizeRequest(state))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login?")))
                .andReturn();

        // Then: no browser-binding cookie
        assertThat(authorize.getResponse().getCookie(TX_COOKIE)).isNull();

        // When: the wallet presents
        MvcResult walletResult = walletPost(state);

        // Then: no cookie for the wallet; the SSE carries the RP redirect with the code, as before
        assertThat(walletResult.getResponse().getHeaders("Set-Cookie")).isEmpty();
        assertThat(sseUrlFor(state)).startsWith(REDIRECT_URI + "?code=").contains("state=" + state);
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private Cookie authorizeInBrowser(String state) throws Exception {
        MvcResult result = mockMvc.perform(authorizeRequest(state))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login?")))
                .andReturn();
        Cookie tx = result.getResponse().getCookie(TX_COOKIE);
        assertThat(tx).as("login-page redirect of an SSO tenant must bind the browser").isNotNull();
        assertThat(tx.isHttpOnly()).isTrue();
        assertThat(tx.getSecure()).isTrue();
        assertThat(tx.getPath()).isEqualTo("/");
        assertThat(tx.getDomain()).isNull();
        assertThat(tx.getMaxAge()).isEqualTo(600);
        return tx;
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorizeRequest(String state) {
        return get("/oidc/authorize")
                .header("X-Forwarded-Proto", "https")
                .header(X_TENANT, TENANT)
                .param("response_type", "code")
                .param("client_id", CLIENT_ID)
                .param("scope", "openid")
                .param("state", state)
                .param("redirect_uri", REDIRECT_URI)
                .param("code_challenge", CODE_CHALLENGE)
                .param("code_challenge_method", "S256");
    }

    private MvcResult walletPost(String state) throws Exception {
        return mockMvc.perform(post("/oid4vp/auth-response")
                        .header("X-Forwarded-Proto", "https")
                        .header(X_TENANT, TENANT)
                        .param("state", state)
                        .param("vp_token", VP_TOKEN_B64))
                .andExpect(status().isOk())
                .andReturn();
    }

    private org.springframework.test.web.servlet.ResultActions browserClose(String closeUrl, Cookie txCookie)
            throws Exception {
        UriComponents close = UriComponentsBuilder.fromUriString(closeUrl).build();
        var request = get(close.getPath())
                .header("X-Forwarded-Proto", "https")
                .header(X_TENANT, TENANT)
                .param("h", close.getQueryParams().getFirst("h"));
        if (txCookie != null) {
            request.cookie(txCookie);
        }
        return mockMvc.perform(request);
    }

    private String sseUrlFor(String state) {
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        verify(sseEmitterStore).send(eq(state), url.capture());
        return url.getValue();
    }

    private static String codeFrom(String location) {
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
    }

    private TenantSsoConfig config(boolean ssoEnabled) {
        return new TenantSsoConfig(TENANT, "", ssoEnabled,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of(EligibleClientConfig.of(CLIENT_ID)));
    }

    private RegisteredClient buildClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .build();
    }
}
