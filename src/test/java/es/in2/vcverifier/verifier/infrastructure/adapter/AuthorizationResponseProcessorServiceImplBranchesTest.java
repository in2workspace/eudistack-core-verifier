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
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.exception.LoginTenantMismatchException;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationLoggerPort;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
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
import java.util.NoSuchElementException;
import java.util.Set;

import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.BROWSER_BINDING_HASH;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

/**
 * Branch coverage for {@link AuthorizationResponseProcessorServiceImpl}: SD-JWT path, DCQL
 * extraction, revocation checks, error mapping to SSE events and nonce/audience validation.
 */
class AuthorizationResponseProcessorServiceImplBranchesTest {

    private static final String STATE = "state-1";
    private static final String TENANT = "sandbox";
    private static final String CLIENT_ID = "did:key:zVerifier";
    private static final String BACKEND_URL = "http://localhost:8080";
    private static final String SD_JWT = "header.payload.sig~disclosure~";
    private static final String SD_JWT_B64 =
            Base64.getEncoder().encodeToString(SD_JWT.getBytes(StandardCharsets.UTF_8));

    @SuppressWarnings("unchecked")
    private final CacheStore<OAuth2AuthorizationRequest> requestCache = mock(CacheStore.class);
    @SuppressWarnings("unchecked")
    private final CacheStore<AuthorizationCodeData> codeCache = mock(CacheStore.class);
    private final VpService vpService = mock(VpService.class);
    private final SdJwtVerificationService sdJwtService = mock(SdJwtVerificationService.class);
    private final RegisteredClientRepository clientRepository = mock(RegisteredClientRepository.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    private final SseEmitterStore sse = mock(SseEmitterStore.class);
    private final BackendConfig backendConfig = mock(BackendConfig.class);
    private final CryptoComponent crypto = mock(CryptoComponent.class);
    private final CredentialSchemaDispatcher dispatcher = mock(CredentialSchemaDispatcher.class);
    private final CredentialVerificationLoggerPort verificationLogger = mock(CredentialVerificationLoggerPort.class);
    private final CredentialStatusVerifier statusVerifier = mock(CredentialStatusVerifier.class);

    private AuthorizationResponseProcessorServiceImpl service;
    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        service = newService(List.of(statusVerifier));
        when(backendConfig.getUrl()).thenReturn(BACKEND_URL);
        when(backendConfig.getAccessTokenExpirationSeconds()).thenReturn(900L);
        when(crypto.getClientId()).thenReturn(CLIENT_ID);
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(true);
        client = RegisteredClient.withId("id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();
        when(clientRepository.findByClientId("client-id")).thenReturn(client);
        when(dispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("cfg", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
        when(requestCache.remove(STATE)).thenReturn(request(Instant.now().plusSeconds(120).getEpochSecond()));
    }

    private AuthorizationResponseProcessorServiceImpl newService(List<CredentialStatusVerifier> verifiers) {
        return new AuthorizationResponseProcessorServiceImpl(requestCache, codeCache, vpService, sdJwtService,
                new ObjectMapper(), clientRepository, authorizationService, sse, backendConfig, crypto,
                verifiers, dispatcher, verificationLogger);
    }

    // --- login window ---

    @Test
    void missingExpiration_sendsInvalidRequestAndThrows() {
        when(requestCache.remove(STATE)).thenReturn(requestWithoutExpiration());

        assertThrows(LoginTimeoutException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("INVALID_REQUEST"), anyString());
        verify(verificationLogger).logVerifiedError(any(), any(LoginTimeoutException.class));
    }

    @Test
    void expiredLogin_sendsLoginTimeout() {
        when(requestCache.remove(STATE)).thenReturn(request(Instant.now().minusSeconds(5).getEpochSecond()));

        assertThrows(LoginTimeoutException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("LOGIN_TIMEOUT"), anyString());
    }

    @Test
    void unknownState_sendsInvalidState() {
        when(requestCache.remove(STATE)).thenReturn(null);

        assertThrows(NoSuchElementException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "INVALID_STATE", "State not found or expired");
    }

    // --- SD-JWT path ---

    @Test
    void sdJwt_notRevoked_issuesCode() {
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1", "idx", 5))));
        when(statusVerifier.isRevoked("https://s/1", "5", "revocation")).thenReturn(false);

        AuthResponseResult result = service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        assertNotNull(result.credentialJson());
        assertTrue(result.redirectUrl().startsWith("https://client.example.com/callback?code="));
        assertEquals("client-id", result.clientId());
        verify(sse, never()).send(anyString(), anyString());
        verify(verificationLogger).logVerifiedOk("cfg");
    }

    @Test
    void sdJwt_revoked_sendsCredentialRevoked() {
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1", "idx", 5))));
        when(statusVerifier.isRevoked("https://s/1", "5", "revocation")).thenReturn(true);

        assertThrows(CredentialRevokedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
    }

    @Test
    void sdJwt_noStatusVerifierRegistered_failsClosed() {
        service = newService(List.of());
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1", "idx", 5))));

        assertThrows(CredentialRevokedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));
    }

    @Test
    void sdJwt_verifierNotSupportingTokenStatusList_failsClosed() {
        when(statusVerifier.supports("TokenStatusListEntry")).thenReturn(false);
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1", "idx", 5))));

        assertThrows(CredentialRevokedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));
    }

    @Test
    void sdJwt_withoutStatusBlock_skipsRevocationCheck() {
        stubSdJwt(Map.of("name", "x"));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    @Test
    void sdJwt_statusWithoutStatusList_skipsRevocationCheck() {
        stubSdJwt(Map.of("status", Map.of("other", 1)));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    @Test
    void sdJwt_statusListMissingUri_skipsRevocationCheck() {
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("idx", 1))));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    @Test
    void sdJwt_statusListBlankUri_skipsRevocationCheck() {
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", " ", "idx", 1))));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    @Test
    void sdJwt_statusListMissingIdx_skipsRevocationCheck() {
        stubSdJwt(Map.of("status", Map.of("status_list", Map.of("uri", "https://s/1"))));

        service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        verify(statusVerifier, never()).isRevoked(anyString(), anyString(), anyString());
    }

    @Test
    void sdJwt_verificationFailure_sendsSignatureInvalid() {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenThrow(new JWTVerificationException("bad sig"));

        assertThrows(JWTVerificationException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("SIGNATURE_INVALID"), anyString());
    }

    @Test
    void sdJwt_unexpectedFailure_sendsValidationError() {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenThrow(new IllegalStateException("boom"));

        assertThrows(IllegalStateException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse, times(2)).sendValidationFailed(eq(STATE), eq("VALIDATION_ERROR"), anyString());
    }

    @Test
    void sdJwt_credentialExpired_sendsCredentialExpired() {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenThrow(new CredentialExpiredException("old"));

        assertThrows(CredentialExpiredException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_EXPIRED", "The credential has expired");
    }

    @Test
    void sdJwt_credentialNotActive_sendsCredentialNotActive() {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenThrow(new CredentialNotActiveException("early"));

        assertThrows(CredentialNotActiveException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_NOT_ACTIVE", "The credential is not yet active");
    }

    @Test
    void sdJwt_issuerNotAuthorized_sendsIssuerNotTrusted() {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenThrow(new IssuerNotAuthorizedException("nope"));

        assertThrows(IssuerNotAuthorizedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "ISSUER_NOT_TRUSTED", "The credential issuer is not trusted");
    }

    // --- dispatcher gating ---

    @Test
    void dispatcher_legacySunsetClosed_sendsFormatGated() {
        stubSdJwt(Map.of("name", "x"));
        when(dispatcher.dispatch(any())).thenThrow(new LegacyFormatSunsetClosedException("closed"));

        assertThrows(LegacyFormatSunsetClosedException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "FORMAT_GATED", "closed");
    }

    @Test
    void dispatcher_bumpedFormatDisabled_sendsFormatGated() {
        stubSdJwt(Map.of("name", "x"));
        when(dispatcher.dispatch(any())).thenThrow(new BumpedFormatTemporarilyDisabledException("off"));

        assertThrows(BumpedFormatTemporarilyDisabledException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "FORMAT_GATED", "off");
    }

    @Test
    void dispatcher_unknownFormat_sendsFormatGated() {
        stubSdJwt(Map.of("name", "x"));
        when(dispatcher.dispatch(any())).thenThrow(new UnknownCredentialFormatException("??"));

        assertThrows(UnknownCredentialFormatException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(STATE, "FORMAT_GATED", "??");
    }

    @Test
    void unknownClient_sendsUnauthorizedClient() {
        stubSdJwt(Map.of("name", "x"));
        when(clientRepository.findByClientId("client-id")).thenReturn(null);

        assertThrows(OAuth2AuthenticationException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("UNAUTHORIZED_CLIENT"), anyString());
    }

    @Test
    void failureAfterVerification_isNotLoggedAsVerificationError() {
        stubSdJwt(Map.of("name", "x"));
        when(clientRepository.findByClientId("client-id")).thenReturn(null);

        assertThrows(OAuth2AuthenticationException.class, () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

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
        stubSdJwt(Map.of("name", "x"));

        service.handleAuthResponse(STATE, b64(dcqlTemplate.formatted(SD_JWT)), TENANT);

        verify(sdJwtService).verifyPresentation(eq(SD_JWT), eq(CLIENT_ID), any());
    }

    @Test
    void dcql_noUsableEntries_throwsParsingException() {
        String vpToken = b64("{\"empty\":[]}");
        var ex = assertThrows(JWTParsingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("no entries"));
    }

    @Test
    void dcql_malformedJson_throwsParsingException() {
        String vpToken = b64("{not json");
        var ex = assertThrows(JWTParsingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("Failed to parse DCQL"));
    }

    // --- JWT VP path ---

    @Test
    void jwtVp_valid_issuesCode() throws Exception {
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString()))
                .thenReturn(new ObjectMapper().readTree("{\"a\":1}"));

        AuthResponseResult result = service.handleAuthResponse(STATE, b64(vp("nonce-1", List.of(CLIENT_ID))), TENANT);

        assertEquals(1, result.credentialJson().get("a").asInt());
    }

    @Test
    void jwtVp_audienceMatchingBackendUrl_isAccepted() throws Exception {
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString()))
                .thenReturn(new ObjectMapper().readTree("{}"));

        service.handleAuthResponse(STATE, b64(vp("nonce-1", List.of(BACKEND_URL))), TENANT);

        verify(vpService).verifyVerifiablePresentation(anyString());
    }

    @Test
    void jwtVp_revokedCredential_sendsCredentialRevoked() throws Exception {
        doThrow(new CredentialRevokedException("revoked"))
                .when(vpService).verifyVerifiablePresentation(anyString());

        String vpToken = b64(vp("nonce-1", List.of(CLIENT_ID)));
        assertThrows(CredentialRevokedException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        verify(sse).sendValidationFailed(STATE, "CREDENTIAL_REVOKED", "The credential has been revoked");
    }

    @Test
    void jwtVp_nonceMismatch_throwsClaimMissing() throws Exception {
        String vpToken = b64(vp("other", List.of(CLIENT_ID)));
        var ex = assertThrows(JWTClaimMissingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("does not match"));
    }

    @Test
    void jwtVp_noCachedNonce_throwsClaimMissing() throws Exception {
        when(requestCache.remove(STATE)).thenReturn(baseRequest()
                .additionalParameters(Map.of(NONCE, "client-nonce",
                        EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond())).build());

        String vpToken = b64(vp("nonce-1", List.of(CLIENT_ID)));
        var ex = assertThrows(JWTClaimMissingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("No nonce found"));
    }

    @Test
    void jwtVp_missingAudience_throwsClaimMissing() throws Exception {
        String vpToken = b64(vp("nonce-1", null));
        var ex = assertThrows(JWTClaimMissingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("'aud' claim is missing"));
    }

    @Test
    void jwtVp_audienceMismatch_throwsClaimMissing() throws Exception {
        String vpToken = b64(vp("nonce-1", List.of("someone-else")));
        var ex = assertThrows(JWTClaimMissingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        assertTrue(ex.getMessage().contains("does not match the verifier"));
    }

    @Test
    void jwtVp_unparseable_throwsParsingException() {
        String vpToken = b64("not-a-jwt");
        assertThrows(JWTParsingException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));
    }

    @Test
    void jwtVp_blankState_throwsClaimMissing() {
        when(requestCache.remove(" ")).thenReturn(request(Instant.now().plusSeconds(60).getEpochSecond()));

        String vpToken = b64("a.b.c");
        assertThrows(JWTClaimMissingException.class,
                () -> service.handleAuthResponse(" ", vpToken, TENANT));
    }

    @Test
    void jwtVp_signatureInvalid_sendsSignatureInvalid() throws Exception {
        doThrow(new JWTVerificationException("bad"))
                .when(vpService).verifyVerifiablePresentation(anyString());

        String vpToken = b64(vp("nonce-1", List.of(CLIENT_ID)));
        assertThrows(JWTVerificationException.class,
                () -> service.handleAuthResponse(STATE, vpToken, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("SIGNATURE_INVALID"), anyString());
    }

    // --- SSO reuse ---

    @Test
    void issueCodeForReusedSession_buildsRedirectUrlWithPkce() throws Exception {
        JsonNode credential = new ObjectMapper().readTree("{\"a\":1}");

        String url = service.issueCodeForReusedSession("client-id", "https://client.example.com/callback",
                Set.of("read"), "st", "challenge", "S256", "n-1", credential);

        assertTrue(url.startsWith("https://client.example.com/callback?code="));
        assertTrue(url.endsWith("&state=st"));
        verify(authorizationService).save(any(OAuth2Authorization.class));
        verify(codeCache).add(anyString(), any(AuthorizationCodeData.class));
    }

    @Test
    void issueCodeForReusedSession_withoutPkceNorNonce_stillIssuesCode() throws Exception {
        String url = service.issueCodeForReusedSession("client-id", "https://client.example.com/callback",
                Set.of("read"), "st", null, null, null, new ObjectMapper().readTree("{}"));

        assertTrue(url.contains("code="));
    }

    @Test
    void issueCodeForReusedSession_unknownClient_throws() {
        when(clientRepository.findByClientId("missing")).thenReturn(null);

        Set<String> scopes = Set.of();

        assertThrows(OAuth2AuthenticationException.class, () -> service.issueCodeForReusedSession("missing",
                "https://client.example.com/callback", scopes, "st", null, null, null, null));
    }

    // --- EUD-252: tenant binding, browser binding, code revocation ---

    @Test
    void tenantMismatch_sendsTenantMismatchAndThrows() {
        when(requestCache.remove(STATE)).thenReturn(baseRequest().additionalParameters(Map.of(
                NONCE, "client-nonce", VP_NONCE, "nonce-1", AUTHORIZE_TENANT, "kpmg",
                EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond())).build());

        assertThrows(LoginTenantMismatchException.class,
                () -> service.handleAuthResponse(STATE, SD_JWT_B64, TENANT));

        verify(sse).sendValidationFailed(eq(STATE), eq("TENANT_MISMATCH"), anyString());
        verify(sdJwtService, never()).verifyPresentation(anyString(), anyString(), any());
    }

    @Test
    void matchingTenantAndBrowserBinding_areCarriedInResult() {
        stubSdJwt(Map.of("name", "x"));
        when(requestCache.remove(STATE)).thenReturn(baseRequest().additionalParameters(Map.of(
                NONCE, "client-nonce", VP_NONCE, "nonce-1", AUTHORIZE_TENANT, TENANT, BROWSER_BINDING_HASH, "abc123",
                EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond())).build());

        AuthResponseResult result = service.handleAuthResponse(STATE, SD_JWT_B64, TENANT);

        assertEquals("abc123", result.browserBindingHash());
        assertNotNull(result.authorizationCode());
        assertTrue(result.toString().contains("bound=true"));
        verify(sdJwtService).verifyPresentation(anyString(), anyString(), eq("nonce-1"));
    }

    @Test
    void revokeAuthorizationCode_existingCode_removesAuthorizationAndSnapshot() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorizationService.findByToken(eq("code-1"), any())).thenReturn(authorization);

        service.revokeAuthorizationCode("code-1");

        verify(authorizationService).remove(authorization);
        verify(codeCache).delete("code-1");
    }

    @Test
    void revokeAuthorizationCode_unknownCode_onlyClearsSnapshot() {
        when(authorizationService.findByToken(eq("code-2"), any())).thenReturn(null);

        service.revokeAuthorizationCode("code-2");

        verify(authorizationService, never()).remove(any());
        verify(codeCache).delete("code-2");
    }

    @Test
    void revokeAuthorizationCode_blankOrNull_isNoOp() {
        service.revokeAuthorizationCode(null);
        service.revokeAuthorizationCode(" ");

        verify(authorizationService, never()).findByToken(any(), any());
    }

    // --- helpers ---

    private void stubSdJwt(Map<String, Object> claims) {
        when(sdJwtService.verifyPresentation(anyString(), anyString(), any()))
                .thenReturn(new SdJwtVerificationResult(new HashMap<>(claims), "vct", null));
    }

    private OAuth2AuthorizationRequest request(long expirationEpoch) {
        return baseRequest().additionalParameters(Map.of(NONCE, "client-nonce", VP_NONCE, "nonce-1", EXPIRATION, expirationEpoch)).build();
    }

    private OAuth2AuthorizationRequest requestWithoutExpiration() {
        return baseRequest().additionalParameters(Map.of(NONCE, "client-nonce")).build();
    }

    private OAuth2AuthorizationRequest.Builder baseRequest() {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
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
