package es.in2.vcverifier.oauth2.infrastructure.filter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import es.in2.vcverifier.oauth2.application.workflow.WalletLoginWorkflow;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.LoginMethod;
import es.in2.vcverifier.verifier.domain.port.TenantLoginMethodsPort;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

import java.net.http.HttpClient;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_METHODS;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
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
    /** RFC 9207 iss: no server context bound here, so the request-derived BackendConfig URL. */
    private static final String ISS_PARAM = "&iss=https%3A%2F%2Fverifier.example.com";
    private static final String LOGIN_REQUIRED_REDIRECT = REDIRECT_URI + "?error=login_required"
            + "&error_description=prompt%3Dnone%3A+end-user+authentication+is+required&state=" + STATE + ISS_PARAM;
    private static final String INTERACTION_REQUIRED_REDIRECT = REDIRECT_URI + "?error=interaction_required"
            + "&error_description=prompt%3Dnone%3A+end-user+interaction+is+required&state=" + STATE + ISS_PARAM;
    private static final String MAX_AGE_INVALID_REDIRECT = REDIRECT_URI + "?error=invalid_request"
            + "&error_description=max_age+must+be+a+non-negative+integer&state=" + STATE + ISS_PARAM;
    private static final String PROMPT_NOT_A_STRING_REDIRECT = REDIRECT_URI + "?error=invalid_request"
            + "&error_description=prompt+must+be+a+string&state=" + STATE + ISS_PARAM;
    private static final String CLAIMS_INVALID_REDIRECT = REDIRECT_URI + "?error=invalid_request"
            + "&error_description=claims+must+be+a+valid+claims+request&state=" + STATE + ISS_PARAM;
    private static final String ACR_VALUES_NOT_A_STRING_REDIRECT = REDIRECT_URI + "?error=invalid_request"
            + "&error_description=acr_values+must+be+a+string&state=" + STATE + ISS_PARAM;
    private static final String HIGH_ACR = "http://eidas.europa.eu/LoA/high";
    private static final long LOGIN_TIMEOUT_SECONDS = 120L;
    private static final long SELECTION_TIMEOUT_SECONDS = 600L;
    private static final String UNMET_REDIRECT = REDIRECT_URI + "?error=unmet_authentication_requirements"
            + "&error_description=no+login+method+meets+the+requested+authentication+requirements&state="
            + STATE + ISS_PARAM;
    /** SsoTtlRange.MAX_ABSOLUTE (24 h) + 1 s. */
    private static final long MAX_AGE_ABOVE_CAP = 86_401L;
    private static final String NONE_COMBINED_REDIRECT = REDIRECT_URI + "?error=invalid_request"
            + "&error_description=prompt%3Dnone+cannot+be+combined+with+other+values&state=" + STATE + ISS_PARAM;

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
    @Mock private TenantLoginMethodsPort tenantLoginMethodsPort;
    @Mock private DcqlProfileResolver dcqlProfileResolver;

    private CustomAuthorizationRequestConverter converter;
    private AuthorizationRedirectException thrown;

    /** The two request shapes that must behave identically. */
    enum Mode { PLAIN, JAR }

    @AfterEach
    void clearAuthorizationServerContext() {
        AuthorizationServerContextHolder.resetContext();
    }

    @BeforeEach
    void setUp() {
        lenient().when(dcqlProfileResolver.requestsAttestation(any())).thenReturn(true);
        converter = new CustomAuthorizationRequestConverter(didService, jwtService, cacheStore, backendConfig,
                registeredClientRepository, false, SELECTION_TIMEOUT_SECONDS, httpClient, authorizationRequestBuildWorkflow,
                safeUrlValidator, reuseSsoSessionWorkflow, ssoBrowserBindingCookie, tenantLoginMethodsPort,
                dcqlProfileResolver, new WalletLoginWorkflow(authorizationRequestBuildWorkflow, backendConfig));
        lenient().when(backendConfig.getLoginTimeoutSeconds()).thenReturn(LOGIN_TIMEOUT_SECONDS);
        lenient().when(tenantLoginMethodsPort.activeLoginMethods(any())).thenReturn(Set.of(LoginMethod.WALLET));

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

    @Test
    void convert_promptAbsentAndReuseFailsWithDriverError_logsClassNamesOnlyAtWarnAndThrowableAtDebug() {
        // Given: a raw driver exception whose message chain carries a session id
        HttpServletRequest request = request(Mode.PLAIN, null, null);
        when(reuseSsoSessionWorkflow.reuse(any(), any(), any(), any(), any()))
                .thenThrow(new IllegalStateException("query failed for " + SESSION_ID,
                        new SQLException("Key (id)=(" + SESSION_ID + ") already exists")));
        Logger logger = (Logger) LoggerFactory.getLogger(CustomAuthorizationRequestConverter.class);
        Level previousLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            // When
            assertQrRedirect(convertExpectingRedirect(request));
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
        }

        // Then
        ILoggingEvent warn = appender.list.stream()
                .filter(e -> e.getLevel() == Level.WARN && e.getFormattedMessage().startsWith("event=sso_reuse_failed"))
                .findFirst().orElseThrow();
        assertEquals("event=sso_reuse_failed tenant=" + TENANT + " clientId=" + CLIENT_ID
                + " error=IllegalStateException rootCause=SQLException", warn.getFormattedMessage());
        assertNull(warn.getThrowableProxy());
        assertTrue(appender.list.stream().anyMatch(e -> e.getLevel() == Level.DEBUG
                && e.getFormattedMessage().startsWith("event=sso_reuse_failed")
                && e.getThrowableProxy() != null
                && e.getThrowableProxy().getClassName().equals(IllegalStateException.class.getName())));
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
        assertEquals(LOGIN_REQUIRED_REDIRECT, error.getUri());
        assertEquals("prompt=none: end-user authentication is required", error.getDescription());
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
        assertEquals(INTERACTION_REQUIRED_REDIRECT, error.getUri());
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
        assertEquals(LOGIN_REQUIRED_REDIRECT, error.getUri());
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
        assertEquals(NONE_COMBINED_REDIRECT, error.getUri());
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

    static Stream<Arguments> unusableRegisteredRedirectUris() {
        // Accepted by RegisteredClient (a java.net.URI without fragment), but no authorization
        // response can be built on them.
        return Stream.of(Mode.values()).flatMap(mode -> Stream.of(
                Arguments.of(mode, "https://client.example.com/café"),
                Arguments.of(mode, "https://client.example.com/callback?x=[1]")));
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("unusableRegisteredRedirectUris")
    void convert_registeredRedirectUriThatCannotCarryAResponse_failsOnTheVerifierErrorPageBeforeReuse(
            Mode mode, String redirectUri) {
        // Given: plain → query redirect_uri; JAR → request-object redirect_uri; both registered as-is
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(RegisteredClient.withId("1")
                .clientId(CLIENT_ID)
                .clientName("Client A")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .build());
        HttpServletRequest request = request(mode, null, null, redirectUri);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);
        Logger logger = (Logger) LoggerFactory.getLogger(CustomAuthorizationRequestConverter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        OAuth2Error error;
        try {
            // When
            error = convertExpectingError(request);
        } finally {
            logger.detachAppender(appender);
        }

        // Then: Verifier error page, never a redirect to that URI; nothing reused, cached or built
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getUri().startsWith("https://verifier.example.com/error?"));
        assertFalse(thrown.isLoginPage());
        verifyNoInteractions(reuseSsoSessionWorkflow, cacheStore, ssoBrowserBindingCookie);
        verify(authorizationRequestBuildWorkflow, never()).validateScope(any());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
        assertTrue(appender.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                && event.getFormattedMessage().equals("event=authorize_redirect_uri_malformed clientId=" + CLIENT_ID)));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_unsupportedScopeWithValidSession_isRejectedBeforeReuse(Mode mode) {
        // Given
        HttpServletRequest request = request(mode, null, null);
        doThrow(new InvalidScopeException("unsupported")).when(authorizationRequestBuildWorkflow).validateScope(SCOPE);

        // When / Then
        assertEquals("invalid_scope", convertExpectingError(request).getErrorCode());
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

    // ---- malformed prompt / max_age → invalid_request (OIDC Core §3.1.2.6) ----

    static Stream<Arguments> malformedMaxAge() {
        return Stream.of(
                Arguments.of(Mode.PLAIN, "-1"),
                Arguments.of(Mode.PLAIN, "abc"),
                Arguments.of(Mode.PLAIN, "1.5"),
                Arguments.of(Mode.PLAIN, "+5"),
                Arguments.of(Mode.PLAIN, "1e3"),
                Arguments.of(Mode.JAR, -1L),
                Arguments.of(Mode.JAR, 300.5),
                Arguments.of(Mode.JAR, Double.NaN),
                Arguments.of(Mode.JAR, "-1"),
                Arguments.of(Mode.JAR, "abc"),
                Arguments.of(Mode.JAR, true),
                Arguments.of(Mode.JAR, List.of(300L)));
    }

    @ParameterizedTest(name = "{0} max_age={1}")
    @MethodSource("malformedMaxAge")
    void convert_malformedMaxAge_returnsInvalidRequestToClient(Mode mode, Object maxAge) {
        // Given: a session that could be reused
        HttpServletRequest request = request(mode, null, maxAge);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then: error to the validated redirect_uri with description, state and iss — no reuse, no QR
        assertEquals("invalid_request", error.getErrorCode());
        assertEquals("max_age must be a non-negative integer", error.getDescription());
        assertEquals(MAX_AGE_INVALID_REDIRECT, error.getUri());
        verifyNoInteractions(reuseSsoSessionWorkflow, ssoBrowserBindingCookie);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    static Stream<Arguments> malformedClaims() {
        return Stream.of(
                Arguments.of(Mode.PLAIN, "{not json"),
                Arguments.of(Mode.PLAIN, "{\"id_token\":{\"acr\":\"" + HIGH_ACR + "\"}}"),
                Arguments.of(Mode.PLAIN, "{\"id_token\":{\"acr\":{\"essential\":\"yes\"}}}"),
                Arguments.of(Mode.JAR, Map.of("id_token", Map.of("acr", Map.of("values", HIGH_ACR)))),
                Arguments.of(Mode.JAR, List.of("acr")));
    }

    @ParameterizedTest(name = "{0} claims={1}")
    @MethodSource("malformedClaims")
    void convert_malformedClaims_returnsInvalidRequestToClient(Mode mode, Object claims) {
        // Given
        HttpServletRequest request = request(mode, Map.of("claims", claims));

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("invalid_request", error.getErrorCode());
        assertEquals(CLAIMS_INVALID_REDIRECT, error.getUri());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void convert_jarAcrValuesNotAString_returnsInvalidRequestToClient() {
        // Given
        HttpServletRequest request = request(Mode.JAR, Map.of("acr_values", List.of(HIGH_ACR)));

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals(ACR_VALUES_NOT_A_STRING_REDIRECT, error.getUri());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    static Stream<Arguments> wellFormedRequestedLevel() {
        return Stream.of(
                Arguments.of(Mode.PLAIN, Map.of("acr_values", HIGH_ACR)),
                Arguments.of(Mode.PLAIN, Map.of("claims",
                        "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":[\"" + HIGH_ACR + "\"]}}}")),
                Arguments.of(Mode.PLAIN, Map.of("acr_values", "urn:example:unknown")),
                Arguments.of(Mode.JAR, Map.of("acr_values", HIGH_ACR)),
                Arguments.of(Mode.JAR, Map.of("claims",
                        Map.of("id_token", Map.of("acr", Map.of("essential", true, "values", List.of(HIGH_ACR)))))));
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("wellFormedRequestedLevel")
    void convert_wellFormedRequestedLevel_continuesToQr(Mode mode, Map<String, Object> parameters) {
        // Given: a wallet whose attestations meet the requested level
        when(dcqlProfileResolver.highestAssuranceLevel(any())).thenReturn(Optional.of(AssuranceLevel.HIGH));
        HttpServletRequest request = request(mode, parameters);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When / Then
        assertQrRedirect(convertExpectingRedirect(request));
    }

    // ---- login methods ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_clientWithoutLoginMethods_cachesOnlyTheWalletAndNoLevel(Mode mode) {
        // Given
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertQrRedirect(convertExpectingRedirect(request));

        // Then
        Map<String, Object> cached = cachedLogin().getAdditionalParameters();
        assertEquals(List.of("wallet"), cached.get("login_methods"));
        assertFalse(cached.containsKey("acr_requested"));
        assertFalse(cached.containsKey("acr_essential"));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_clientWithBothMethods_cachesThemInTheirOrder(Mode mode) {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertStateOnlyRedirect(convertExpectingRedirect(request));

        // Then
        assertEquals(List.of("x509", "wallet"), cachedLogin().getAdditionalParameters().get("login_methods"));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_tenantWithoutCertificate_cachesOnlyTheWallet(Mode mode) {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertQrRedirect(convertExpectingRedirect(request));

        // Then
        assertEquals(List.of("wallet"), cachedLogin().getAdditionalParameters().get("login_methods"));
    }

    @Test
    void convert_essentialLevelOnlyTheCertificateMeets_cachesTheCertificateAndTheRequestedLevel() {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        when(dcqlProfileResolver.highestAssuranceLevel(any())).thenReturn(Optional.of(AssuranceLevel.SUBSTANTIAL));
        HttpServletRequest request = request(Mode.PLAIN, Map.of("claims",
                "{\"id_token\":{\"acr\":{\"essential\":true,\"value\":\"" + HIGH_ACR + "\"}}}"));
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertStateOnlyRedirect(convertExpectingRedirect(request));

        // Then
        Map<String, Object> cached = cachedLogin().getAdditionalParameters();
        assertEquals(List.of("x509"), cached.get("login_methods"));
        assertEquals(HIGH_ACR, cached.get("acr_requested"));
        assertEquals(true, cached.get("acr_essential"));
    }

    // ---- reuse by login method, level and attestation scopes ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_reuse_receivesTheClientMethodsTheEssentialLevelAndTheAttestationScopes(Mode mode) {
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(dcqlProfileResolver.requestsAttestation(any())).thenReturn(true);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        convertExpectingRedirect(request(mode, Map.of("claims", essentialHighClaims(mode))));

        AuthorizationContext ctx = capturedReuseContext();
        assertEquals(List.of(LoginMethod.X509, LoginMethod.WALLET), ctx.loginMethods());
        assertEquals(AssuranceLevel.HIGH, ctx.essentialLevel());
        assertTrue(ctx.attestationScopes());
        verify(authorizationRequestBuildWorkflow).validateScope(SCOPE);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_reuseForACertificateClientWithoutAttestationScopes_doesNotRequireADcqlScope(Mode mode) {
        registerClientWithLoginMethods(List.of(LoginMethod.X509));
        when(dcqlProfileResolver.requestsAttestation(any())).thenReturn(false);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        convertExpectingRedirect(request(mode, null, null));

        assertFalse(capturedReuseContext().attestationScopes());
        verify(authorizationRequestBuildWorkflow, never()).validateScope(any());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_reuseForAWalletOnlyClient_stillValidatesTheScope(Mode mode) {
        registerClientWithLoginMethods(List.of(LoginMethod.WALLET));
        when(dcqlProfileResolver.requestsAttestation(any())).thenReturn(false);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        convertExpectingRedirect(request(mode, null, null));

        verify(authorizationRequestBuildWorkflow).validateScope(SCOPE);
        assertNull(capturedReuseContext().essentialLevel());
    }

    // ---- redirect by login methods ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_noLoginMethodLeft_returnsUnmetAuthenticationRequirementsToClient(Mode mode) {
        // Given: a wallet-only client whose attestations fall short of the essential level
        registerClientWithLoginMethods(List.of(LoginMethod.WALLET));
        when(dcqlProfileResolver.highestAssuranceLevel(any())).thenReturn(Optional.of(AssuranceLevel.SUBSTANTIAL));
        HttpServletRequest request = request(mode, Map.of("claims", essentialHighClaims(mode)));
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then: error to the validated redirect_uri with its state — no wallet request, no cached login
        assertEquals("unmet_authentication_requirements", error.getErrorCode());
        assertEquals(UNMET_REDIRECT, error.getUri());
        assertFalse(thrown.isLoginPage());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
        verify(cacheStore, never()).putIfAbsent(any(), any());
        verifyNoInteractions(ssoBrowserBindingCookie);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_onlyTheWallet_signsTheWalletRequestAndRedirectsWithIt(Mode mode) {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertQrRedirect(convertExpectingRedirect(request));

        // Then
        verify(authorizationRequestBuildWorkflow).buildAuthorizationRequest(any(), any(), eq(STATE), any());
        assertEquals("vp-nonce", cachedLogin().getAdditionalParameters().get("vp_nonce"));
        assertEquals("openid4vp://...", cachedLogin().getAdditionalParameters().get("wallet_auth_request"));
        assertExpiresIn(LOGIN_TIMEOUT_SECONDS);
    }

    @Test
    void convert_withAccessProfile_cachesItForALaterWalletRequest() {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(Mode.PLAIN, Map.of("access_profile", "issuer_access"));
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertStateOnlyRedirect(convertExpectingRedirect(request));

        // Then
        Map<String, Object> cached = cachedLogin().getAdditionalParameters();
        assertEquals("issuer_access", cached.get("access_profile"));
        assertFalse(cached.containsKey("wallet_auth_request"));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_twoMethods_redirectsWithOnlyTheStateWithoutSigningTheWalletRequest(Mode mode) {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509, LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertStateOnlyRedirect(convertExpectingRedirect(request));

        // Then
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
        assertFalse(cachedLogin().getAdditionalParameters().containsKey("vp_nonce"));
        assertExpiresIn(SELECTION_TIMEOUT_SECONDS);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_onlyTheCertificate_redirectsWithOnlyTheStateWithoutSigningTheWalletRequest(Mode mode) {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.X509));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(mode, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertStateOnlyRedirect(convertExpectingRedirect(request));

        // Then
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
        assertEquals(List.of("x509"), cachedLogin().getAdditionalParameters().get("login_methods"));
    }

    @Test
    void convert_stateOnlyRedirect_usesTheClientLoginPage() {
        // Given
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(RegisteredClient.withId("1")
                .clientId(CLIENT_ID)
                .clientName("Client A")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .clientSettings(ClientSettings.builder()
                        .setting(CLIENT_SETTING_LOGIN_METHODS, List.of(LoginMethod.X509, LoginMethod.WALLET))
                        .setting(CLIENT_SETTING_LOGIN_PAGE_URI, "https://login.tenant-a.example.com/login")
                        .build())
                .build());
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET, LoginMethod.X509));
        HttpServletRequest request = request(Mode.PLAIN, null, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then
        assertEquals("https://login.tenant-a.example.com/login?state=" + STATE, error.getUri());
        assertTrue(thrown.isLoginPage());
    }

    @Test
    void convert_walletLevelComesFromTheClientScopes() {
        // Given
        registerClientWithLoginMethods(List.of(LoginMethod.WALLET));
        when(tenantLoginMethodsPort.activeLoginMethods(TENANT)).thenReturn(Set.of(LoginMethod.WALLET));
        HttpServletRequest request = request(Mode.PLAIN, Map.of("acr_values", HIGH_ACR));
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertQrRedirect(convertExpectingRedirect(request));

        // Then
        verify(dcqlProfileResolver).highestAssuranceLevel(Set.of("openid", "learcredential"));
        assertEquals(false, cachedLogin().getAdditionalParameters().get("acr_essential"));
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_malformedMaxAgeWithPromptLogin_isStillInvalidRequest(Mode mode) {
        // Given: prompt=login never attempts reuse, but the request is malformed anyway
        HttpServletRequest request = request(mode, "login", "-5");

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals(MAX_AGE_INVALID_REDIRECT, error.getUri());
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    static Stream<Arguments> wellFormedMaxAge() {
        return Stream.of(
                Arguments.of(Mode.PLAIN, "300", 300L),
                Arguments.of(Mode.PLAIN, "0", 0L),
                Arguments.of(Mode.JAR, 300L, 300L),
                Arguments.of(Mode.JAR, 300.0, 300L),
                Arguments.of(Mode.JAR, "300", 300L));
    }

    @ParameterizedTest(name = "{0} max_age={1}")
    @MethodSource("wellFormedMaxAge")
    void convert_wellFormedMaxAge_isPassedToReuse(Mode mode, Object maxAge, long expectedSeconds) {
        // Given
        HttpServletRequest request = request(mode, null, maxAge);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        assertQrRedirect(convertExpectingRedirect(request));

        // Then
        assertEquals(expectedSeconds, capturedReuseContext().maxAge());
    }

    static Stream<Arguments> unenforceableMaxAge() {
        return Stream.of(
                Arguments.of(Mode.PLAIN, ""),
                Arguments.of(Mode.PLAIN, String.valueOf(MAX_AGE_ABOVE_CAP)),
                Arguments.of(Mode.PLAIN, "99999999999999999999999999"),
                Arguments.of(Mode.JAR, MAX_AGE_ABOVE_CAP),
                Arguments.of(Mode.JAR, 1e300));
    }

    @ParameterizedTest(name = "{0} max_age={1}")
    @MethodSource("unenforceableMaxAge")
    void convert_emptyOrAboveMaxTtlMaxAge_isTreatedAsAbsent(Mode mode, Object maxAge) {
        // Given: valid input that cannot force freshness (or no value at all)
        HttpServletRequest request = request(mode, null, maxAge);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingRedirect(request);

        // Then: reuse proceeds as without max_age
        assertEquals(REUSE_REDIRECT, error.getUri());
        assertNull(capturedReuseContext().maxAge());
    }

    static Stream<Object> nonStringPrompt() {
        return Stream.of(List.of("none"), 1L, true, Map.of("value", "none"));
    }

    @ParameterizedTest
    @MethodSource("nonStringPrompt")
    void convert_jarPromptClaimNotAString_returnsInvalidRequestToClient(Object prompt) {
        // Given: absent would mean reuse; a malformed prompt must not be read as absent
        HttpServletRequest request = request(Mode.JAR, prompt, null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("invalid_request", error.getErrorCode());
        assertEquals("prompt must be a string", error.getDescription());
        assertEquals(PROMPT_NOT_A_STRING_REDIRECT, error.getUri());
        verifyNoInteractions(reuseSsoSessionWorkflow);
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_malformedMaxAgeWithUnregisteredRedirectUri_isRejectedOnTheVerifierErrorPage(Mode mode) {
        // Given: the error must never go to a redirect_uri that was not validated first
        HttpServletRequest request = request(mode, null, "-1");
        if (mode == Mode.PLAIN) {
            when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(MALICIOUS_REDIRECT_URI);
        } else {
            when(jwtService.extractClaimFromPayload(any(), eq(OAuth2ParameterNames.REDIRECT_URI)))
                    .thenReturn(MALICIOUS_REDIRECT_URI);
        }

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getUri().startsWith("https://verifier.example.com/error?"));
    }

    @Test
    void convert_jarMalformedMaxAgeWithInvalidSignature_failsOnTheSignatureFirst() {
        // Given
        HttpServletRequest request = request(Mode.JAR, null, -1L);
        doThrow(new IllegalArgumentException("bad signature")).when(jwtService).verifyJWTWithECKey(anyString(), any());

        // When / Then: no redirect to the request-object redirect_uri before the signature is verified
        assertThrows(IllegalArgumentException.class, () -> converter.convert(request));
    }

    // ---- authorization response shape (RFC 6749 §3.1.2 / RFC 9207) ----

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_errorToRedirectUriWithQuery_keepsItsQueryAndAddsTheResponseParams(Mode mode) {
        // Given: the registered redirect_uri has its own query
        String redirectUriWithQuery = REDIRECT_URI + "?tenant=a&x=1%202";
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(RegisteredClient.withId("1")
                .clientId(CLIENT_ID)
                .clientName("Client A")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUriWithQuery)
                .build());
        HttpServletRequest request = request(mode, "none", null, redirectUriWithQuery);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then: one well-formed query, the client's parameters untouched
        assertEquals(redirectUriWithQuery + "&error=login_required"
                + "&error_description=prompt%3Dnone%3A+end-user+authentication+is+required&state=" + STATE + ISS_PARAM,
                error.getUri());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void convert_withAuthorizationServerContext_usesItsIssuerAsIss(Mode mode) {
        // Given: the issuer Spring Authorization Server resolved for this host (= discovery issuer)
        AuthorizationServerContext context = mock(AuthorizationServerContext.class);
        when(context.getIssuer()).thenReturn("https://tenant-a.example.com/verifier");
        AuthorizationServerContextHolder.setContext(context);
        HttpServletRequest request = request(mode, "none", null);
        stubReuse(ReuseSsoSessionWorkflow.Result.Status.INTERACTION_REQUIRED);

        // When
        OAuth2Error error = convertExpectingError(request);

        // Then: on the error response and on the context the reuse code is issued with
        assertTrue(error.getUri().endsWith("&iss=https%3A%2F%2Ftenant-a.example.com%2Fverifier"), error.getUri());
        assertEquals("https://tenant-a.example.com/verifier", capturedReuseContext().issuer());
    }

    @Test
    void convert_qrFlow_cachesTheIssuerWithTheRequest() {
        // Given: the code and abort responses of the QR flow read iss from the cached request
        HttpServletRequest request = request(Mode.PLAIN, "login", null);
        when(cacheStore.putIfAbsent(eq(STATE), any())).thenReturn(null);

        // When
        convertExpectingRedirect(request);

        // Then
        ArgumentCaptor<OAuth2AuthorizationRequest> cached = ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
        verify(cacheStore).putIfAbsent(eq(STATE), cached.capture());
        assertEquals("https://verifier.example.com", cached.getValue().getAuthorizationUri());
    }

    // ---- helpers ----

    /**
     * Builds a valid request with an SSO cookie for {@link #TENANT}. In JAR mode {@code prompt} and
     * {@code max_age} go into the request-object claims with their Java type (JSON type); in PLAIN
     * mode into the query, as strings.
     */
    private HttpServletRequest request(Mode mode, Object prompt, Object maxAge) {
        return request(mode, prompt, maxAge, REDIRECT_URI);
    }

    private HttpServletRequest request(Mode mode, Object prompt, Object maxAge, String redirectUri) {
        return request(mode, prompt, maxAge, redirectUri, Map.of());
    }

    private HttpServletRequest request(Mode mode, Map<String, Object> extraParameters) {
        return request(mode, null, null, REDIRECT_URI, extraParameters);
    }

    private HttpServletRequest request(Mode mode, Object prompt, Object maxAge, String redirectUri,
                                       Map<String, Object> extraParameters) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://verifier.example.com/oidc/authorize"));
        when(request.getHeader("X-Forwarded-Host")).thenReturn("verifier.example.com");
        when(request.getHeader("X-Forwarded-Proto")).thenReturn("https");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENT_ID);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(STATE);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(SCOPE);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn(TENANT);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("__Secure-sso-" + TENANT, SESSION_ID)});

        if (mode == Mode.PLAIN) {
            when(request.getParameter("request")).thenReturn(null);
            when(request.getParameter("prompt")).thenReturn(prompt == null ? null : prompt.toString());
            when(request.getParameter("max_age")).thenReturn(maxAge == null ? null : maxAge.toString());
            extraParameters.forEach((name, value) -> when(request.getParameter(name)).thenReturn(value.toString()));
            return request;
        }

        when(request.getParameter("request")).thenReturn(JWT);
        Map<String, Object> claims = new HashMap<>();
        claims.put(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
        claims.put(OAuth2ParameterNames.SCOPE, SCOPE);
        claims.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        if (prompt != null) {
            claims.put("prompt", prompt);
        }
        if (maxAge != null) {
            claims.put("max_age", maxAge); // as given: Long = JSON integer, Double = JSON decimal, ...
        }
        claims.putAll(extraParameters);
        SignedJWT signedJwt = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(jwtService.parseJWT(JWT)).thenReturn(signedJwt);
        when(signedJwt.getPayload()).thenReturn(payload);
        when(signedJwt.serialize()).thenReturn(JWT);
        when(payload.toJSONObject()).thenReturn(claims);
        when(jwtService.extractClaimFromPayload(eq(payload), anyString()))
                .thenAnswer(inv -> (String) claims.get(inv.<String>getArgument(1)));
        PublicKey publicKey = mock(PublicKey.class);
        when(didService.resolvePublicKeyFromDid(CLIENT_ID)).thenReturn(publicKey);
        return request;
    }

    private void registerClientWithLoginMethods(List<LoginMethod> loginMethods) {
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(RegisteredClient.withId("1")
                .clientId(CLIENT_ID)
                .clientName("Client A")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope("openid")
                .scope("learcredential")
                .clientSettings(ClientSettings.builder()
                        .setting(CLIENT_SETTING_LOGIN_METHODS, loginMethods)
                        .build())
                .build());
    }

    private void assertExpiresIn(long seconds) {
        long expiration = ((Number) cachedLogin().getAdditionalParameters().get("expiration")).longValue();
        long expected = java.time.Instant.now().plusSeconds(seconds).getEpochSecond();
        assertTrue(expiration >= expected - 1 && expiration <= expected,
                () -> "expected expiration in " + seconds + " s, got " + (expiration - java.time.Instant.now().getEpochSecond()));
    }

    private OAuth2AuthorizationRequest cachedLogin() {
        ArgumentCaptor<OAuth2AuthorizationRequest> captor = ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
        verify(cacheStore).putIfAbsent(eq(STATE), captor.capture());
        return captor.getValue();
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

    private void assertStateOnlyRedirect(OAuth2Error error) {
        assertEquals("https://verifier.example.com/login?state=" + STATE, error.getUri());
        assertTrue(thrown.isLoginPage());
        verify(ssoBrowserBindingCookie).bindIfSsoEnabled(any());
    }

    private static Object essentialHighClaims(Mode mode) {
        return mode == Mode.PLAIN
                ? "{\"id_token\":{\"acr\":{\"essential\":true,\"value\":\"" + HIGH_ACR + "\"}}}"
                : Map.of("id_token", Map.of("acr", Map.of("essential", true, "value", HIGH_ACR)));
    }

    private void assertQrRedirect(OAuth2Error error) {
        assertTrue(error.getUri().contains(QR_REDIRECT_MARKER), () -> "expected QR redirect, got " + error.getUri());
        assertTrue(thrown.isLoginPage());
        verify(ssoBrowserBindingCookie).bindIfSsoEnabled(any());
    }
}
