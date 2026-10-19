package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.http.HttpClient;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * EUD-300 FR-03/FR-05 — SSO reuse decision at {@code /oidc/authorize} (OIDC Core 1.0 §3.1.2.1),
 * for both the plain query request and the JAR request object (RFC 9101).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomAuthorizationRequestConverterSsoReuseTest {

    private static final String TENANT = "tenant-a";
    private static final String CLIENT_ID = "did:key:client-a";
    private static final String STATE = "s-1";
    private static final String SCOPE = "openid learcredential";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String MALICIOUS_REDIRECT_URI = "https://attacker.example.com/callback";
    private static final String SESSION_ID = "session-id";
    private static final String JWT = "request-object";
    private static final String REUSE_REDIRECT = REDIRECT_URI + "?code=c&state=" + STATE;
    private static final String QR_REDIRECT_MARKER = "/login?authRequest=";

    @Mock private DIDService didService;
    @Mock private JWTService jwtService;
    @Mock private CacheStore<OAuth2AuthorizationRequest> cacheStore;
    @Mock private BackendConfig backendConfig;
    @Mock private RegisteredClientRepository registeredClientRepository;
    @Mock private HttpClient httpClient;
    @Mock private AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;
    @Mock private SafeUrlValidator safeUrlValidator;
    @Mock private ReuseSsoSessionWorkflow reuseSsoSessionWorkflow;
    @Mock private SsoBrowserBindingCookie ssoBrowserBindingCookie;

    private CustomAuthorizationRequestConverter converter;
    private AuthorizationRedirectException thrown;

    /** The two request shapes that must behave identically. */
    enum Mode { PLAIN, JAR }

    @BeforeEach
    void setUp() {
        converter = new CustomAuthorizationRequestConverter(didService, jwtService, cacheStore, backendConfig,
                registeredClientRepository, false, 120L, httpClient, authorizationRequestBuildWorkflow,
                safeUrlValidator, reuseSsoSessionWorkflow, ssoBrowserBindingCookie);

        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(RegisteredClient.withId("1")
                .clientId(CLIENT_ID)
                .clientName("Client A")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .build());
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(any(), any(), any(), any()))
                .thenReturn(new AuthorizationRequestBuildWorkflow.Result("jwt", "openid4vp://...", "qr", "vp-nonce"));
    }

    // ---- prompt absent ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptAbsentAndReuseAllowed_redirectsWithCodeWithoutQr(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then
        assertEquals(REUSE_REDIRECT, error.getUri());
        assertFalse(thrown.isLoginPage());
        verify(authorizationRequestBuildWorkflow).validateScope(SCOPE);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
        verifyNoInteractions(ssoBrowserBindingCookie);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptAbsentAndNoSession_continuesToQrWithoutError(Mode mode) {
        // Given: no cookie → the workflow answers LOGIN_REQUIRED
        HttpServletRequest request = request(mode, null, null);
        when(request.getCookies()).thenReturn(null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then
        assertQrRedirect(error);
        verify(reuseSsoSessionWorkflow).reuse(eq(TENANT), eq(null), any(), eq(CLIENT_ID), anyString());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptAbsentAndClientNotInCatalog_continuesToQrWithoutError(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.INTERACTION_REQUIRED);

        // When / Then
        assertQrRedirect(convertExpectingRedirect(request));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptAbsentAndMaxAgeExceeded_continuesToQrAndPassesMaxAge(Mode mode) {
        // Given: max_age=10 → the policy rejects an older session (LOGIN_REQUIRED)
        HttpServletRequest request = request(mode, null, 10L);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then
        assertQrRedirect(error);
        assertEquals(10L, capturedReuseContext().maxAge());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptAbsentAndReuseFailsUnexpectedly_continuesToQr(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, null, null);
        when(reuseSsoSessionWorkflow.reuse(any(), any(), any(), any(), any()))
                .thenThrow(new IllegalStateException("boom"));

        // When / Then
        assertQrRedirect(convertExpectingRedirect(request));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptWithOnlyUnsupportedValues_isTreatedAsAbsent(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "consent select_account", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When / Then
        assertEquals(REUSE_REDIRECT, convertExpectingRedirect(request).getUri());
    }

    // ---- prompt=none (unchanged behaviour) ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptNoneAndReuseAllowed_redirectsWithCode(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "none", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then
        assertEquals(REUSE_REDIRECT, error.getUri());
        verifyNoInteractions(ssoBrowserBindingCookie);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptNoneAndLoginRequired_returnsLoginRequiredToClient(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "none", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("login_required", error.getErrorCode());
        assertEquals(REDIRECT_URI + "?error=login_required&state=" + STATE, error.getUri());
        assertFalse(thrown.isLoginPage());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptNoneAndInteractionRequired_returnsInteractionRequiredToClient(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "none", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.INTERACTION_REQUIRED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("interaction_required", error.getErrorCode());
        assertEquals(REDIRECT_URI + "?error=interaction_required&state=" + STATE, error.getUri());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptNoneWithoutTenant_returnsLoginRequiredWithoutQr(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "none", null);
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn(null);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("login_required", error.getErrorCode());
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    // ---- prompt=login / invalid combinations ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptLoginWithValidSession_continuesToQrWithoutReuse(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "login", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When / Then
        assertQrRedirect(convertExpectingRedirect(request));
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_promptNoneCombinedWithLogin_returnsInvalidRequestToClient(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, "none login", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("invalid_request", error.getErrorCode());
        assertEquals(REDIRECT_URI + "?error=invalid_request&state=" + STATE, error.getUri());
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    // ---- validation happens before any reuse ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_unregisteredRedirectUriWithValidSession_isRejectedBeforeReuse(Mode mode) {
        // Given: plain → query redirect_uri; JAR → request-object redirect_uri
        HttpServletRequest request = request(mode, "none", null);
        if (mode == Mode.PLAIN) {
            when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(MALICIOUS_REDIRECT_URI);
        } else {
            when(jwtService.extractClaimFromPayload(any(), eq(OAuth2ParameterNames.REDIRECT_URI)))
                    .thenReturn(MALICIOUS_REDIRECT_URI);
        }
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then: Verifier error page, never the attacker's URI
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getUri().startsWith("https://verifier.example.com/error?"));
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_unsupportedScopeWithValidSession_isRejectedBeforeReuse(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, null, null);
        doThrow(new InvalidScopeException("unsupported")).when(authorizationRequestBuildWorkflow).validateScope(SCOPE);

        // When / Then
        assertThrows(InvalidScopeException.class, () -> converter.convert(request));
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    @Test
    void convert_jarWithInvalidSignature_isRejectedBeforeReuse() {
        // Given
        HttpServletRequest request = request(Mode.JAR, null, null);
        doThrow(new IllegalArgumentException("bad signature")).when(jwtService).verifyJWTWithECKey(anyString(), any());

        // When / Then
        assertThrows(IllegalArgumentException.class, () -> converter.convert(request));
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    // ---- JAR: the request object is authoritative (RFC 9101 §6.3) ----

    @Test
    void convert_jarWithPromptNoneOnlyInQuery_ignoresQueryPrompt() {
        // Given: prompt=none in the query, absent from the request object
        HttpServletRequest request = request(Mode.JAR, null, null);
        when(request.getParameter("prompt")).thenReturn("none");
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When / Then: absent-prompt behaviour (QR), not the prompt=none error
        assertQrRedirect(convertExpectingRedirect(request));
    }

    @Test
    void convert_jarWithMaxAgeInQueryAndRequestObject_usesRequestObjectValueAndRedirectUri() {
        // Given
        HttpServletRequest request = request(Mode.JAR, null, 30L);
        when(request.getParameter("max_age")).thenReturn("9999");
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        convertExpectingRedirect(request);

        // Then
        AuthorizationContext ctx = capturedReuseContext();
        assertEquals(30L, ctx.maxAge());
        assertEquals(REDIRECT_URI, ctx.redirectUri());
    }

    // ---- helpers ----

    /**
     * Builds a valid request with an SSO cookie for {@link #TENANT}. In JAR mode {@code prompt} and
     * {@code max_age} go into the request-object claims; in PLAIN mode into the query.
     */
    private HttpServletRequest request(Mode mode, String prompt, Long maxAge) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://verifier.example.com/oidc/authorize"));
        when(request.getHeader("X-Forwarded-Host")).thenReturn("verifier.example.com");
        when(request.getHeader("X-Forwarded-Proto")).thenReturn("https");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENT_ID);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(STATE);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(SCOPE);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn(TENANT);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("__Secure-sso-" + TENANT, SESSION_ID)});

        if (mode == Mode.PLAIN) {
            when(request.getParameter("request")).thenReturn(null);
            when(request.getParameter("prompt")).thenReturn(prompt);
            when(request.getParameter("max_age")).thenReturn(maxAge == null ? null : maxAge.toString());
            return request;
        }

        when(request.getParameter("request")).thenReturn(JWT);
        Map<String, Object> claims = new HashMap<>();
        claims.put(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
        claims.put(OAuth2ParameterNames.SCOPE, SCOPE);
        claims.put(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI);
        if (prompt != null) {
            claims.put("prompt", prompt);
        }
        if (maxAge != null) {
            claims.put("max_age", maxAge); // numeric claim, as Nimbus parses JSON integers
        }
        SignedJWT signedJwt = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(jwtService.parseJWT(JWT)).thenReturn(signedJwt);
        when(signedJwt.getPayload()).thenReturn(payload);
        when(signedJwt.serialize()).thenReturn(JWT);
        when(payload.toJSONObject()).thenReturn(claims);
        when(jwtService.extractClaimFromPayload(eq(payload), anyString()))
                .thenAnswer(inv -> (String) claims.get(inv.<String>getArgument(1)));
        when(didService.resolvePublicKeyFromDid(CLIENT_ID)).thenReturn(mock(PublicKey.class));
        return request;
    }

    private void stubReuse(ReuseSsoSessionWorkflow.Result.Status status) {
        when(reuseSsoSessionWorkflow.reuse(eq(TENANT), any(), any(), eq(CLIENT_ID), anyString()))
                .thenReturn(new ReuseSsoSessionWorkflow.Result(status,
                        status == ReuseSsoSessionWorkflow.Result.Status.ALLOWED ? REUSE_REDIRECT : null));
    }

    private AuthorizationContext capturedReuseContext() {
        ArgumentCaptor<AuthorizationContext> captor = ArgumentCaptor.forClass(AuthorizationContext.class);
        verify(reuseSsoSessionWorkflow).reuse(eq(TENANT), eq(SESSION_ID), captor.capture(), eq(CLIENT_ID), anyString());
        return captor.getValue();
    }

    /** Next-hop redirect (QR page or SSO-reuse code redirect), both modelled as required_external_user_authentication. */
    private OAuth2Error convertExpectingRedirect(HttpServletRequest request) {
        OAuth2Error error = convertExpectingError(request);
        assertEquals("required_external_user_authentication", error.getErrorCode());
        return error;
    }

    /** Every redirect the converter decides on is the dedicated type the error handler follows. */
    private OAuth2Error convertExpectingError(HttpServletRequest request) {
        thrown = assertThrows(AuthorizationRedirectException.class, () -> converter.convert(request));
        return thrown.getError();
    }

    private void assertQrRedirect(OAuth2Error error) {
        assertTrue(error.getUri().contains(QR_REDIRECT_MARKER), () -> "expected QR redirect, got " + error.getUri());
        assertTrue(thrown.isLoginPage());
        verify(ssoBrowserBindingCookie).bindIfSsoEnabled(any());
    }
}
