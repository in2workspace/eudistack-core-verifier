package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationService;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.CredentialSchemaValidationException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dcql.ClaimQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.CredentialQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationLoggerPort;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import es.in2.vcverifier.verifier.domain.service.CredentialValidator;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

/**
 * Behaviour of {@link AuthorizationResponseProcessorServiceImpl} not covered by
 * {@link AuthorizationResponseProcessorServiceImplTest}: the SD-JWT path with its fail-closed
 * revocation check, DCQL token extraction, mapping of verification errors to SSE events, JWT VP
 * nonce/audience validation and the SSO-reuse code issuance.
 *
 * <p>Stubs are declared per test (never in {@code setUp}) so that strict stubbing flags any stub a
 * test does not actually use.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationResponseProcessorServiceImplSdJwtAndErrorMappingTest {

    private static final String STATE = "state-1";
    private static final String TENANT = "sandbox";
    private static final String CLIENT_ID = "did:key:zVerifier";
    private static final String BACKEND_URL = "http://localhost:8080";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String VP_NONCE_VALUE = "nonce-1";
    private static final String SD_JWT = "header.payload.sig~disclosure~";
    private static final String SD_JWT_B64 =
            Base64.getEncoder().encodeToString(SD_JWT.getBytes(StandardCharsets.UTF_8));
    private static final Map<String, Object> REVOCABLE_CLAIMS =
            Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1", "idx", 5)));

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> requestCache;
    @Mock
    private CacheStore<AuthorizationCodeData> codeCache;
    @Mock
    private VpService vpService;
    @Mock
    private SdJwtVerificationService sdJwtService;
    @Mock
    private RegisteredClientRepository clientRepository;
    @Mock
    private OAuth2AuthorizationService authorizationService;
    @Mock
    private SseEmitterStore sse;
    @Mock
    private BackendConfig backendConfig;
    @Mock
    private CryptoComponent crypto;
    @Mock
    private CredentialSchemaDispatcher dispatcher;
    @Mock
    private CredentialVerificationLoggerPort verificationLogger;
    @Mock
    private CredentialStatusVerifier statusVerifier;
    @Mock
    private DcqlProfileResolver dcqlProfileResolver;
    @Mock
    private CredentialValidator credentialValidator;

    private AuthorizationResponseProcessorServiceImpl service;
    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        service = newService(List.of(statusVerifier));
        client = RegisteredClient.withId("id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope("read")
                .build();
    }

    private AuthorizationResponseProcessorServiceImpl newService(List<CredentialStatusVerifier> verifiers) {
        return new AuthorizationResponseProcessorServiceImpl(requestCache, codeCache, vpService, sdJwtService,
                new ObjectMapper(), clientRepository, authorizationService, sse, backendConfig, crypto,
                verifiers, dispatcher, verificationLogger, dcqlProfileResolver, credentialValidator);
    }

    // --- login window ---

    @Test
    void missingExpiration_sendsInvalidRequestAndThrows() {
        givenLogin(requestWithoutExpiration());

        assertThrows(LoginTimeoutException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("INVALID_REQUEST"), anyString());
        verify(verificationLogger).logVerifiedError(any(), any(LoginTimeoutException.class));
        assertNoCodeIssued();
    }

    // --- SD-JWT path ---

    @Test
    void sdJwt_notRevoked_issuesCode() {
        givenSuccessfulSdJwtLogin(REVOCABLE_CLAIMS);
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(true);
        when(statusVerifier.isRevoked("https://s/1", "5", "revocation")).thenReturn(false);

        AuthResponseResult result = service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        assertNotNull(result.credentialJson());
        assertTrue(result.redirectUrl().startsWith(REDIRECT_URI + "?code="));
        assertEquals("client-id", result.clientId());
        verify(sse, never()).send(anyString(), anyString());
        verify(verificationLogger).logVerifiedOk("cfg");
    }

    @Test
    void sdJwt_revoked_sendsCredentialRevokedAndIssuesNoCode() {
        givenVerifiedSdJwt(REVOCABLE_CLAIMS);
        givenOpenLoginWith();
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(true);
        when(statusVerifier.isRevoked("https://s/1", "5", "revocation")).thenReturn(true);

        var ex = assertThrows(CredentialRevokedException.class,
                () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        assertTrue(ex.getMessage().contains("SD-JWT credential is revoked"));
        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_noStatusVerifierRegistered_failsClosed() {
        service = newService(List.of());
        givenVerifiedSdJwt(REVOCABLE_CLAIMS);
        givenOpenLoginWith();

        var ex = assertThrows(CredentialRevokedException.class,
                () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        assertTrue(ex.getMessage().contains("no CredentialStatusVerifier registered"));
        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_verifierNotSupportingTokenStatusList_failsClosed() {
        givenVerifiedSdJwt(REVOCABLE_CLAIMS);
        givenOpenLoginWith();
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(false);

        var ex = assertThrows(CredentialRevokedException.class,
                () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        assertTrue(ex.getMessage().contains("no CredentialStatusVerifier registered"));
        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_statusListCommunicationFailure_failsClosed() {
        assertStatusCheckFailureFailsClosed(new FailedCommunicationException("status list unreachable"));
    }

    @Test
    void sdJwt_statusListSignatureInvalid_failsClosed() {
        assertStatusCheckFailureFailsClosed(new StatusListCredentialException("status list signature invalid"));
    }

    /** If revocation cannot be determined, the error must propagate and no authorization code may be issued. */
    private void assertStatusCheckFailureFailsClosed(RuntimeException statusFailure) {
        givenVerifiedSdJwt(REVOCABLE_CLAIMS);
        givenOpenLoginWith();
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(true);
        when(statusVerifier.isRevoked("https://s/1", "5", "revocation")).thenThrow(statusFailure);

        var ex = assertThrows(statusFailure.getClass(), () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        assertSame(statusFailure, ex);
        // reported by verifyPresentation and again by the catch-all of handleAuthResponse
        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains(statusFailure.getMessage()));
        verify(sse, never()).sendValidationFailed(eq(STATE), eq("CREDENTIAL_REVOKED"), anyString());
        verify(verificationLogger).logVerifiedError(null, statusFailure);
        verify(verificationLogger, never()).logVerifiedOk(anyString());
        assertNoCodeIssued();
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-status", "status-without-status-list", "missing-uri", "blank-uri", "missing-idx"})
    void sdJwt_noUsableStatusList_skipsRevocationCheck(String scenario) {
        givenSuccessfulSdJwtLogin(claimsFor(scenario));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    private static Map<String, Object> claimsFor(String scenario) {
        return switch (scenario) {
            case "no-status" -> Map.of("name", "x");
            case "status-without-status-list" -> Map.of("status", Map.of("other", 1));
            case "missing-uri" -> Map.of("status", Map.of("status_list", Map.of("idx", 1)));
            case "blank-uri" -> Map.of("status", Map.of("status_list", Map.of("uri", " ", "idx", 1)));
            case "missing-idx" -> Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1")));
            default -> throw new IllegalArgumentException(scenario);
        };
    }

    @Test
    void sdJwt_verificationFailure_sendsSignatureInvalid() {
        givenOpenLoginWith();
        givenSdJwtVerificationThrows(new JWTVerificationException("bad sig"));

        assertThrows(JWTVerificationException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("SIGNATURE_INVALID"), contains("bad sig"));
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_schemaValidationFails_sendsValidationErrorAndIssuesNoCode() {
        // Arrange
        givenOpenLoginWith();
        givenSdJwtVerifiedAs(Map.of("name", "x"));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(new DcqlQuery(List.of()));
        when(credentialValidator.validate(any(), any())).thenReturn(ValidationResult.builder()
                .valid(false).credentialType("vct").errors(List.of("givenName is required")).build());

        // Act
        var ex = assertThrows(CredentialSchemaValidationException.class,
                () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        // Assert
        assertTrue(ex.getMessage().contains("givenName is required"));
        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains("givenName is required"));
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_dcqlNamesClaims_passesThemToSchemaValidation() {
        // Arrange
        givenOpenLoginWith();
        givenSdJwtVerifiedAs(Map.of("name", "x"));
        CredentialQuery.CredentialMeta meta = new CredentialQuery.CredentialMeta(List.of("vct"), null);
        when(dcqlProfileResolver.resolve("read")).thenReturn(new DcqlQuery(List.of(
                new CredentialQuery("q1", "dc+sd-jwt", meta, List.of(
                        new ClaimQuery(List.of("givenName"), null, null),
                        new ClaimQuery(List.of("familyName"), null, null))))));
        when(credentialValidator.validate(any(), any()))
                .thenReturn(ValidationResult.builder().valid(true).errors(List.of()).build());
        givenDispatch();
        givenRegisteredClient();
        givenCodeIssuance();

        // Act
        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        // Assert
        verify(credentialValidator).validate(any(), eq(Set.of("givenName", "familyName")));
    }

    @Test
    void sdJwt_unexpectedFailure_sendsValidationError() {
        givenOpenLoginWith();
        givenSdJwtVerificationThrows(new IllegalStateException("boom"));

        assertThrows(IllegalStateException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains("boom"));
        assertNoCodeIssued();
    }

    @Test
    void sdJwt_credentialExpired_sendsCredentialExpired() {
        givenOpenLoginWith();
        givenSdJwtVerificationThrows(new CredentialExpiredException("old"));

        assertThrows(CredentialExpiredException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_EXPIRED", "The credential has expired");
    }

    @Test
    void sdJwt_credentialNotActive_sendsCredentialNotActive() {
        givenOpenLoginWith();
        givenSdJwtVerificationThrows(new CredentialNotActiveException("early"));

        assertThrows(CredentialNotActiveException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_NOT_ACTIVE", "The credential is not yet active");
    }

    @Test
    void sdJwt_issuerNotAuthorized_sendsIssuerNotTrusted() {
        givenOpenLoginWith();
        givenSdJwtVerificationThrows(new IssuerNotAuthorizedException("nope"));

        assertThrows(IssuerNotAuthorizedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "ISSUER_NOT_TRUSTED", "The credential issuer is not trusted");
    }

    // --- dispatcher gating ---

    @Test
    void dispatcher_legacySunsetClosed_sendsFormatGated() {
        assertDispatchRejection(new LegacyFormatSunsetClosedException("closed"));
    }

    @Test
    void dispatcher_bumpedFormatDisabled_sendsFormatGated() {
        assertDispatchRejection(new BumpedFormatTemporarilyDisabledException("off"));
    }

    @Test
    void dispatcher_unknownFormat_sendsFormatGated() {
        assertDispatchRejection(new UnknownCredentialFormatException("??"));
    }

    private void assertDispatchRejection(RuntimeException rejection) {
        givenOpenLoginWith();
        givenVerifiedSdJwt(Map.of("name", "x"));
        when(dispatcher.dispatch(any())).thenThrow(rejection);

        assertThrows(rejection.getClass(), () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "FORMAT_GATED", rejection.getMessage());
        assertNoCodeIssued();
    }

    @Test
    void failureAfterVerification_isNotLoggedAsVerificationError() {
        givenOpenLoginWith();
        givenVerifiedSdJwt(Map.of("name", "x"));
        givenDispatch();
        when(clientRepository.findByClientId("client-id")).thenReturn(null);

        assertThrows(OAuth2AuthenticationException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("UNAUTHORIZED_CLIENT"), anyString());
        verify(verificationLogger).logVerifiedOk("cfg");
        verify(verificationLogger, never()).logVerifiedError(any(), any());
    }

    // --- DCQL ---

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"query_1\":[\"%s\"]}",
            "{\"query_1\":\"%s\"}",
            "{\"empty\":[],\"num\":3,\"ok\":[\"%s\"]}"
    })
    void dcql_entryShapes_extractVpToken(String dcqlTemplate) {
        givenSuccessfulSdJwtLogin(Map.of("name", "x"));

        service.handleAuthResponse(STATE, b64(dcqlTemplate.formatted(SD_JWT)), TENANT);

        verify(sdJwtService).verifyPresentation(SD_JWT, CLIENT_ID, VP_NONCE_VALUE);
    }

    @Test
    void dcql_noUsableEntries_throwsParsingException() {
        givenOpenLoginWith();
        String vpToken = b64("{\"empty\":[]}");

        var ex = assertThrows(JWTParsingException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("no entries"));
        verify(sse).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains("no entries"));
        assertNoCodeIssued();
    }

    @Test
    void dcql_malformedJson_throwsParsingException() {
        givenOpenLoginWith();
        String vpToken = b64("{not json");

        var ex = assertThrows(JWTParsingException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("Failed to parse DCQL"));
        verify(sse).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains("Failed to parse DCQL"));
        assertNoCodeIssued();
    }

    // --- JWT VP path ---

    @Test
    void jwtVp_valid_issuesCode() throws Exception {
        givenOpenLoginWith();
        givenClientId();
        givenDispatch();
        givenRegisteredClient();
        givenCodeIssuance();
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString()))
                .thenReturn(new ObjectMapper().readTree("{\"a\":1}"));

        AuthResponseResult result = service.handleAuthResponse(STATE, b64(vp(VP_NONCE_VALUE, List.of(CLIENT_ID))), TENANT);

        assertEquals(1, result.credentialJson().get("a").asInt());
        verify(authorizationService).save(any(OAuth2Authorization.class));
    }

    @Test
    void jwtVp_audienceMatchingBackendUrl_isAccepted() throws Exception {
        givenOpenLoginWith();
        givenClientId();
        givenDispatch();
        givenRegisteredClient();
        givenCodeIssuance();
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString()))
                .thenReturn(new ObjectMapper().readTree("{}"));

        service.handleAuthResponse(STATE, b64(vp(VP_NONCE_VALUE, List.of(BACKEND_URL))), TENANT);

        verify(vpService).verifyVerifiablePresentation(anyString());
        verify(authorizationService).save(any(OAuth2Authorization.class));
    }

    @Test
    void jwtVp_revokedCredential_sendsCredentialRevoked() throws Exception {
        givenOpenLoginWith();
        givenClientId();
        givenBackendUrl();
        doThrow(new CredentialRevokedException("revoked"))
                .when(vpService).verifyVerifiablePresentation(anyString());

        String vpToken = b64(vp(VP_NONCE_VALUE, List.of(CLIENT_ID)));
        assertThrows(CredentialRevokedException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
        assertNoCodeIssued();
    }

    @Test
    void jwtVp_noCachedNonce_throwsClaimMissing() throws Exception {
        givenLogin(baseRequest().additionalParameters(Map.of(NONCE, "client-nonce",
                EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond())).build());

        String vpToken = b64(vp(VP_NONCE_VALUE, List.of(CLIENT_ID)));
        var ex = assertThrows(JWTClaimMissingException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("No nonce found"));
        assertRejectedBeforeVpVerification("No nonce found");
    }

    @Test
    void jwtVp_withoutNonceClaim_failsWithNullPointerBeforeVerification() throws Exception {
        givenOpenLoginWith();

        String vpToken = b64(vp(null, List.of(CLIENT_ID)));
        // Documents current behaviour: `getClaim(NONCE).toString()` throws an NPE, so the
        // `vpNonce == null` branch is unreachable. Fixing production is tracked separately.
        assertThrows(NullPointerException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), anyString());
        verify(vpService, never()).verifyVerifiablePresentation(any());
        assertNoCodeIssued();
    }

    @Test
    void jwtVp_audienceMismatch_throwsClaimMissing() throws Exception {
        givenOpenLoginWith();
        givenClientId();
        givenBackendUrl();

        String vpToken = b64(vp(VP_NONCE_VALUE, List.of("someone-else")));
        var ex = assertThrows(JWTClaimMissingException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("does not match the verifier"));
        assertRejectedBeforeVpVerification("does not match the verifier");
    }

    @Test
    void jwtVp_blankState_throwsClaimMissing() {
        when(requestCache.remove(" ")).thenReturn(request(Instant.now().plusSeconds(60).getEpochSecond()));

        String vpToken = b64("a.b.c");
        assertThrows(JWTClaimMissingException.class, () -> service.handleAuthResponse(" ", vpToken, TENANT));

        verify(vpService, never()).verifyVerifiablePresentation(any());
        assertNoCodeIssued();
    }

    @Test
    void jwtVp_signatureInvalid_sendsSignatureInvalid() throws Exception {
        givenOpenLoginWith();
        givenClientId();
        givenBackendUrl();
        doThrow(new JWTVerificationException("bad"))
                .when(vpService).verifyVerifiablePresentation(anyString());

        String vpToken = b64(vp(VP_NONCE_VALUE, List.of(CLIENT_ID)));
        assertThrows(JWTVerificationException.class, () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("SIGNATURE_INVALID"), anyString());
        assertNoCodeIssued();
    }

    // --- result ---

    @Test
    void authResponseResult_toString_doesNotLeakCodeOrCredential() {
        givenSuccessfulSdJwtLogin(Map.of("name", "very-secret-claim"));

        AuthResponseResult result = service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        String printed = result.toString();
        assertNotNull(result.authorizationCode());
        assertFalse(printed.contains(result.authorizationCode()));
        assertFalse(printed.contains("very-secret-claim"));
        assertFalse(printed.contains("code="));
    }

    // --- SSO reuse ---

    @Test
    void issueCodeForReusedSession_persistsPkceAndNonceWithTheIssuedCode() throws Exception {
        givenRegisteredClient();
        givenCodeIssuance();
        JsonNode credential = new ObjectMapper().readTree("{\"a\":1}");

        String url = service.issueCodeForReusedSession("client-id", REDIRECT_URI,
                Set.of("read"), "st", "challenge", "S256", "n-1", credential);

        ArgumentCaptor<OAuth2Authorization> authorization = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(authorization.capture());
        OAuth2Authorization saved = authorization.getValue();
        String issuedCode = saved.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue();

        assertTrue(url.startsWith(REDIRECT_URI + "?code=" + issuedCode));
        assertTrue(url.endsWith("&state=st"));
        assertEquals("challenge", saved.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        assertEquals("S256", saved.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));
        OAuth2AuthorizationRequest savedRequest = saved.getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertNotNull(savedRequest);
        assertEquals("challenge", savedRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE));
        assertEquals("S256", savedRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD));
        assertEquals("n-1", savedRequest.getAdditionalParameters().get(NONCE));

        ArgumentCaptor<AuthorizationCodeData> codeData = ArgumentCaptor.forClass(AuthorizationCodeData.class);
        verify(codeCache).add(eq(issuedCode), codeData.capture());
        assertEquals("n-1", codeData.getValue().clientNonce());
        assertSame(credential, codeData.getValue().verifiableCredential());
    }

    @Test
    void issueCodeForReusedSession_withoutPkceNorNonce_issuesCodeWithoutThoseAttributes() throws Exception {
        givenRegisteredClient();
        givenCodeIssuance();

        String url = service.issueCodeForReusedSession("client-id", REDIRECT_URI,
                Set.of("read"), "st", null, null, null, new ObjectMapper().readTree("{}"));

        ArgumentCaptor<OAuth2Authorization> authorization = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(authorization.capture());
        OAuth2Authorization saved = authorization.getValue();

        assertTrue(url.contains("code="));
        assertNull(saved.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        assertNull(saved.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));
        OAuth2AuthorizationRequest savedRequest = saved.getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertNotNull(savedRequest);
        assertFalse(savedRequest.getAdditionalParameters().containsKey(PkceParameterNames.CODE_CHALLENGE));
        assertFalse(savedRequest.getAdditionalParameters().containsKey(PkceParameterNames.CODE_CHALLENGE_METHOD));
        assertFalse(savedRequest.getAdditionalParameters().containsKey(NONCE));
    }

    @Test
    void issueCodeForReusedSession_unknownClient_throwsAndIssuesNoCode() {
        when(clientRepository.findByClientId("missing")).thenReturn(null);

        Set<String> scopes = Set.of();

        assertThrows(OAuth2AuthenticationException.class, () -> service.issueCodeForReusedSession("missing",
                REDIRECT_URI, scopes, "st", null, null, null, null));

        assertNoCodeIssued();
    }

    // --- EUD-252: code revocation edge cases not covered by the sibling test ---

    @Test
    void revokeAuthorizationCode_blankOrNull_isNoOp() {
        service.revokeAuthorizationCode(null);
        service.revokeAuthorizationCode(" ");

        verify(authorizationService, never()).findByToken(any(), any());
        verify(codeCache, never()).delete(any());
    }

    // --- stubbing helpers (each one is used by the test that calls it) ---

    private void givenLogin(OAuth2AuthorizationRequest request) {
        when(requestCache.remove(STATE)).thenReturn(request);
    }

    /** A login of this tenant that has not expired and carries the OID4VP nonce {@value #VP_NONCE_VALUE}. */
    private void givenOpenLoginWith() {
        givenLogin(request(Instant.now().plusSeconds(120).getEpochSecond()));
    }

    private void givenClientId() {
        when(crypto.getClientId()).thenReturn(CLIENT_ID);
    }

    private void givenBackendUrl() {
        when(backendConfig.getUrl()).thenReturn(BACKEND_URL);
    }

    private void givenCodeIssuance() {
        givenBackendUrl();
        when(backendConfig.getAccessTokenExpirationSeconds()).thenReturn(900L);
    }

    private void givenRegisteredClient() {
        when(clientRepository.findByClientId("client-id")).thenReturn(client);
    }

    private void givenDispatch() {
        when(dispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("cfg", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
    }

    private void givenVerifiedSdJwt(Map<String, Object> claims) {
        givenSdJwtVerifiedAs(claims);
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(new DcqlQuery(List.of()));
        when(credentialValidator.validate(any(), any()))
                .thenReturn(ValidationResult.builder().valid(true).errors(List.of()).build());
    }

    private void givenSdJwtVerifiedAs(Map<String, Object> claims) {
        givenClientId();
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenReturn(new SdJwtVerificationResult(new HashMap<>(claims), "vct", null));
    }

    private void givenSdJwtVerificationThrows(RuntimeException failure) {
        givenClientId();
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any())).thenThrow(failure);
    }

    /** Everything a SD-JWT login needs to reach the end and issue an authorization code. */
    private void givenSuccessfulSdJwtLogin(Map<String, Object> claims) {
        givenOpenLoginWith();
        givenVerifiedSdJwt(claims);
        givenDispatch();
        givenRegisteredClient();
        givenCodeIssuance();
    }

    // --- assertion helpers ---

    private void assertNoCodeIssued() {
        verify(authorizationService, never()).save(any());
        verify(codeCache, never()).add(anyString(), any());
    }

    /** The VP is rejected by the nonce/audience check: not verified, no code, reported over SSE. */
    private void assertRejectedBeforeVpVerification(String reason) {
        verify(vpService, never()).verifyVerifiablePresentation(any());
        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), contains(reason));
        assertNoCodeIssued();
    }

    // --- fixtures ---

    private OAuth2AuthorizationRequest request(long expirationEpoch) {
        return baseRequest().additionalParameters(
                Map.of(NONCE, "client-nonce", VP_NONCE, VP_NONCE_VALUE, EXPIRATION, expirationEpoch)).build();
    }

    private OAuth2AuthorizationRequest requestWithoutExpiration() {
        return baseRequest().additionalParameters(Map.of(NONCE, "client-nonce")).build();
    }

    private OAuth2AuthorizationRequest.Builder baseRequest() {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri(REDIRECT_URI)
                .state(STATE)
                .scope("read");
    }

    private static String vp(String nonce, List<String> audience) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().claim(NONCE, nonce)
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
        if (audience != null) {
            claims.audience(audience);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef"));
        return jwt.serialize();
    }

    private static String b64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
