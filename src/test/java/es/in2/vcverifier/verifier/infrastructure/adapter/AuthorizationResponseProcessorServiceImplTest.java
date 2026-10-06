package es.in2.vcverifier.verifier.infrastructure.adapter;
import es.in2.vcverifier.verifier.domain.service.VpService;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationService;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.verifier.domain.exception.LoginTenantMismatchException;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationLoggerPort;
import es.in2.vcverifier.verifier.infrastructure.adapter.AuthorizationResponseProcessorServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.NoSuchElementException;

import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.BROWSER_BINDING_HASH;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@ExtendWith(MockitoExtension.class)
class AuthorizationResponseProcessorServiceImplTest {

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private VpService vpService;

    @Mock
    private SdJwtVerificationService sdJwtVerificationService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Mock
    private SseEmitterStore sseEmitterStore;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private CredentialSchemaDispatcher credentialSchemaDispatcher;

    @Mock
    private CredentialVerificationLoggerPort credentialVerificationLogger;

    @Mock
    private AuthorizationResponseProcessorServiceImpl authorizationResponseProcessorService;

    @BeforeEach
    void setUp() {
        authorizationResponseProcessorService = new AuthorizationResponseProcessorServiceImpl(
                cacheStoreForOAuth2AuthorizationRequest,
                cacheStoreForAuthorizationCodeData,
                vpService,
                sdJwtVerificationService,
                new ObjectMapper(),
                registeredClientRepository,
                oAuth2AuthorizationService,
                sseEmitterStore,
                backendConfig,
                cryptoComponent,
                java.util.List.of(),
                credentialSchemaDispatcher,
                credentialVerificationLogger
        );
        lenient().when(backendConfig.getUrl()).thenReturn("http://localhost:8080");
        lenient().when(backendConfig.getAccessTokenExpirationSeconds()).thenReturn(900L);
        lenient().when(cryptoComponent.getClientId()).thenReturn("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");
    }


    @Test
    void handleAuthResponse_validInput_shouldProcessSuccessfully() throws JOSEException {
        // Arrange
        String state = "test-state";
        String nonce = "test-nonce";

        String vpToken = createVpToken(nonce);
        long timeout = 120L;

        Map<String, Object> additionalParams = Map.of(VP_NONCE, nonce,
                NONCE, nonce,
                EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()
        );

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(additionalParams)
                .scope("read")
                .build();

        RegisteredClient registeredClient = RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();


        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString())).thenReturn(null);
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(registeredClient);

        doNothing().when(oAuth2AuthorizationService).save(any(OAuth2Authorization.class));

        // Act
        AuthResponseResult result = authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null);

        // Assert — EUD-252: the success redirect is returned to the caller, never pushed over SSE here
        verify(sseEmitterStore, never()).send(anyString(), anyString());
        assertEquals(state, result.state());
        String redirectUrl = result.redirectUrl();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("code=" + result.authorizationCode()));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.startsWith("https://client.example.com/callback?"));
        assertEquals("https://client.example.com/callback", result.redirectUri());
        assertEquals("client-id", result.clientId());
        assertEquals("https://auth.example.com", result.authorizationServerBaseUrl());
        assertNull(result.browserBindingHash(), "unbound login (no SSO) carries no binding hash");

        verify(oAuth2AuthorizationService).save(any(OAuth2Authorization.class));
        verify(credentialVerificationLogger).logVerifiedOk("test-config-id");
        verify(credentialVerificationLogger, never()).logVerifiedError(any(), any());
    }

    @Test
    void handleAuthResponse_invalidState_shouldThrowNoSuchElementException() {
        // Arrange
        String state = "invalid-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenThrow(new NoSuchElementException("Value is not present."));

        // Act & Assert
        NoSuchElementException exception = assertThrows(NoSuchElementException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null)
        );

        assertEquals("Value is not present.", exception.getMessage());

        // Verify that delete was not called
        verify(cacheStoreForOAuth2AuthorizationRequest, never()).delete(state);
    }


    @Test
    void handleAuthResponse_invalidVpToken_shouldThrowException() throws JOSEException {
        // Arrange
        String state = "test-state";
        String vpToken = createVpToken(state);
        long timeout = 120L;

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .additionalParameters(Map.of(VP_NONCE, state, EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()))
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);


        doThrow(new RuntimeException("Something failed")).when(vpService).verifyVerifiablePresentation(anyString());

        // Act & Assert
        assertThrows(RuntimeException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null)
        );

        // Failed before the dispatcher ever ran → no bounded type is known, so it tags "unknown".
        verify(credentialVerificationLogger).logVerifiedError(isNull(), any(Throwable.class));
        verify(credentialVerificationLogger, never()).logVerifiedOk(any());
    }

    @Test
    void handleAuthResponse_noRegisteredClient_shouldThrowException() throws JOSEException {
        // Arrange
        String state = "test-state";
        long timeout = 120L;
        String vpToken = createVpToken(state);

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .additionalParameters(Map.of(VP_NONCE, state, EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()))
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(null);
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null)
        );
        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());

        // The credential DID verify successfully — the client-not-registered failure happens
        // afterwards and must not be double-counted as a verification error.
        verify(credentialVerificationLogger).logVerifiedOk("test-config-id");
        verify(credentialVerificationLogger, never()).logVerifiedError(any(), any());
    }

    private String createVpToken(String nonce) throws JOSEException {
        // Build JWT claims with matching 'aud'
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("did:key:abc123")
                .audience("http://localhost:8080")
                .claim(NONCE, nonce)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();

        // Create JWT header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        // Sign the JWT using a dummy secret
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        MACSigner signer = new MACSigner("12345678901234567890123456789012"); // dummy secret 256-bit
        signedJWT.sign(signer);

        // Serialize and encode the token
        return Base64.getEncoder().encodeToString(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void handleAuthResponse_validInput_shouldThrowLoginTimeoutException() {
        String state = "test-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));
        long timeout = 120L;

        Map<String, Object> additionalParams = Map.of(
                NONCE, "test-nonce",
                EXPIRATION, Instant.now().minusSeconds(timeout).getEpochSecond()
        );

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(additionalParams)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        LoginTimeoutException exception = assertThrows(LoginTimeoutException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null)
        );

        assertEquals("Login time has expired", exception.getMessage());

        verify(cacheStoreForOAuth2AuthorizationRequest, times(1)).delete(state);
        verify(credentialVerificationLogger).logVerifiedError(isNull(), any(Throwable.class));
    }


    @Test
    void validateVpAudience_shouldThrowException_whenAudClaimIsMissing() throws Exception {
        // Arrange
        String nonce = "test-nonce";
        String jwtWithoutAud = createJwtWithoutAudience(nonce); // JWT with no 'aud' claim
        String vpToken = Base64.getEncoder().encodeToString(jwtWithoutAud.getBytes(StandardCharsets.UTF_8));

        // Mock mínimo del flujo necesario para que se ejecute validateVpAudience
        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(VP_NONCE, nonce, EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );

        String stateKey = "state";
        when(cacheStoreForOAuth2AuthorizationRequest.get(stateKey)).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(stateKey);



        // Act & Assert
        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(stateKey, vpToken, null)
        );
        String errorMsg ="The 'aud' claim is missing in the VP token.";
        assertEquals(errorMsg, exception.getMessage());
    }
    @Test
    void validateVpAudience_shouldThrowException_whenNonceClaimIsBlank() throws Exception {
            // Arrange
            String jwtWithoutAud =  createJwtWithoutAudience("") ;
            String vpToken = Base64.getEncoder().encodeToString(jwtWithoutAud.getBytes(StandardCharsets.UTF_8));

            // Mock mínimo del flujo necesario para que se ejecute validateVpAudience
            OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
            when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                    Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
            );

            String stateKey = "state";
            when(cacheStoreForOAuth2AuthorizationRequest.get(stateKey)).thenReturn(mockOAuth2AuthorizationRequest);
            doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(stateKey);

            // Act & Assert
            JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                    authorizationResponseProcessorService.handleAuthResponse(stateKey, vpToken, null)
            );

            assertEquals("The 'nonce' claim is missing in the VP token.", exception.getMessage());
        }
    @Test
    void validateVpAudience_shouldThrowException_whenNonceClaimIsNotMatchCached() throws Exception {
        // Arrange
        String jwtWithoutAud = createJwtWithoutAudience("test-nonce"); // JWT with no 'aud' claim
        String vpToken = Base64.getEncoder().encodeToString(jwtWithoutAud.getBytes(StandardCharsets.UTF_8));

        // Mock mínimo del flujo necesario para que se ejecute validateVpAudience
        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(VP_NONCE, "test-nonce2", EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );

        String stateKey = "state";
        when(cacheStoreForOAuth2AuthorizationRequest.get(stateKey)).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(stateKey);



        // Act & Assert
        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(stateKey, vpToken, null)
        );
        assertEquals("VP nonce does not match the cached nonce for the given state.", exception.getMessage());
    }

    @Test
    void validateVpAudience_shouldThrowException_whenStateClaimIsMissing() throws Exception {
        // Arrange
        String jwtWithNonce = createJwtWithoutAudience("test-nonce");
        String vpToken = Base64.getEncoder().encodeToString(jwtWithNonce.getBytes(StandardCharsets.UTF_8));

        String blankState = " ";

        OAuth2AuthorizationRequest mockAuthRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockAuthRequest.getAdditionalParameters()).thenReturn(
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );

        when(cacheStoreForOAuth2AuthorizationRequest.get(blankState)).thenReturn(mockAuthRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(blankState);

        // Act & Assert
        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(blankState, vpToken, null)
        );

        assertEquals("The 'state' claim is missing in the VP token.", exception.getMessage());
    }
    @Test
    void validateVpAudience_shouldThrowException_whenCacheStateIsNull() throws Exception {
        String jwtWithoutAud = createJwtWithoutAudience("test-nonce");
        String vpToken = Base64.getEncoder().encodeToString(jwtWithoutAud.getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );

        String stateKey = "state";
        when(cacheStoreForOAuth2AuthorizationRequest.get(stateKey)).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(stateKey);


        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(stateKey, vpToken, null)
        );

        assertEquals("No nonce found in cache for state=state", exception.getMessage());
    }


    @Test
    void handleAuthResponse_shouldThrowJwtParsingException_whenVpTokenIsMalformed() {
        // Arrange
        String invalidJwt = "malformed.token.value"; // not a valid JWT
        String vpToken = Base64.getEncoder().encodeToString(invalidJwt.getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );

        String stateKey = "state";
        when(cacheStoreForOAuth2AuthorizationRequest.get(stateKey)).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(stateKey);

        // Act & Assert
        JWTParsingException exception = assertThrows(JWTParsingException.class, () ->
                authorizationResponseProcessorService.handleAuthResponse(stateKey, vpToken, null)
        );

        assertEquals("Failed to parse the VP JWT or extract claims.", exception.getMessage());
    }

    private String createJwtWithoutAudience(String nonce) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("did:key:abc123")
                .claim(NONCE, nonce)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        MACSigner signer = new MACSigner("12345678901234567890123456789012"); // dummy secret 256-bit
        signedJWT.sign(signer);

        return signedJWT.serialize();

    }

    @Test
    void handleAuthResponse_withPkce_setsCodeChallengeAttributes() throws Exception {

        String state  = "state-pkce";
        String nonce  = "nonce-pkce";
        String chall  = "abcDEF123_-";
        String method = "S256";
        String vpToken = createVpToken(nonce);

        long timeout = 120L;
        Map<String, Object> addl = Map.of(VP_NONCE, nonce,
                NONCE, nonce,
                EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond(),
                PkceParameterNames.CODE_CHALLENGE, chall,
                PkceParameterNames.CODE_CHALLENGE_METHOD, method
        );

        OAuth2AuthorizationRequest req = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(addl)
                .scope("read")
                .build();

        RegisteredClient rc = RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(req);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        doNothing().when(vpService).verifyVerifiablePresentation(anyString());
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString())).thenReturn(null);
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(rc);

        ArgumentCaptor<OAuth2Authorization> authCap = ArgumentCaptor.forClass(OAuth2Authorization.class);
        doNothing().when(oAuth2AuthorizationService).save(authCap.capture());

        authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null);

        OAuth2Authorization saved = authCap.getValue();
        assertNotNull(saved);

        assertEquals(chall,  saved.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        assertEquals(method, saved.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));

        verify(sseEmitterStore, never()).send(anyString(), anyString());
    }

    @Test
    void handleAuthResponse_withoutPkce_doesNotSetPkceAttributes() throws Exception {
        String state = "state-no-pkce";
        String nonce = "nonce-no-pkce";
        String vpToken = createVpToken(nonce);

        long timeout = 120L;
        Map<String, Object> addl = Map.of(VP_NONCE, nonce,
                NONCE, nonce,
                EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond(),
                PkceParameterNames.CODE_CHALLENGE, "   "
        );

        OAuth2AuthorizationRequest req = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(addl)
                .scope("read")
                .build();

        RegisteredClient rc = RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(req);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        doNothing().when(vpService).verifyVerifiablePresentation(anyString());
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(anyString())).thenReturn(null);
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(rc);

        ArgumentCaptor<OAuth2Authorization> authCap = ArgumentCaptor.forClass(OAuth2Authorization.class);
        doNothing().when(oAuth2AuthorizationService).save(authCap.capture());

        authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null);

        OAuth2Authorization saved = authCap.getValue();
        assertNotNull(saved);
        assertNull(saved.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        assertNull(saved.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));
    }


    @Test
    void handleAuthResponse_browserBoundLogin_returnsBindingHashFromCachedRequest() throws Exception {
        // Given: /authorize bound this login to a browser (SSO tenant)
        String state = "state-bound";
        String nonce = "nonce-bound";
        String vpToken = createVpToken(nonce);
        OAuth2AuthorizationRequest req = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://tenant-a.example.com/verifier")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(Map.of(VP_NONCE, nonce,
                        NONCE, nonce,
                        EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond(),
                        BROWSER_BINDING_HASH, "binding-hash"))
                .scope("read")
                .build();
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(req);
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
        when(registeredClientRepository.findByClientId("client-id")).thenReturn(RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build());

        // When
        AuthResponseResult result = authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null);

        // Then
        assertEquals("binding-hash", result.browserBindingHash());
        assertEquals("https://tenant-a.example.com/verifier", result.authorizationServerBaseUrl());
        assertFalse(result.toString().contains(result.authorizationCode()), "toString must not leak the code");
    }

    @Test
    void revokeAuthorizationCode_knownCode_removesAuthorizationAndCodeData() {
        // Given
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(oAuth2AuthorizationService.findByToken(eq("the-code"), any(OAuth2TokenType.class))).thenReturn(authorization);

        // When
        authorizationResponseProcessorService.revokeAuthorizationCode("the-code");

        // Then
        verify(oAuth2AuthorizationService).remove(authorization);
        verify(cacheStoreForAuthorizationCodeData).delete("the-code");
    }

    @Test
    void revokeAuthorizationCode_unknownCode_isNoOpOnAuthorizationService() {
        // Given
        when(oAuth2AuthorizationService.findByToken(eq("gone"), any(OAuth2TokenType.class))).thenReturn(null);

        // When
        authorizationResponseProcessorService.revokeAuthorizationCode("gone");

        // Then
        verify(oAuth2AuthorizationService, never()).remove(any());
        verify(cacheStoreForAuthorizationCodeData).delete("gone");
    }

    // ---- EUD-252 (F1): the wallet must answer through the tenant the login started on ----

    private OAuth2AuthorizationRequest tenantBoundRequest(String state, String nonce, String tenant) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://tenant-a.example.com/verifier")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(Map.of(
                        VP_NONCE, nonce,
                        AUTHORIZE_TENANT, tenant,
                        EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond()))
                .scope("read")
                .build();
    }

    @Test
    void handleAuthResponse_tenantMismatch_rejectsWithoutIssuingCode() throws JOSEException {
        // Given: login started on tenant-a, wallet answers through tenant-b
        String state = "state-tenant";
        String vpToken = createVpToken("n");
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(tenantBoundRequest(state, "n", "tenant-a"));

        // When / Then
        assertThrows(LoginTenantMismatchException.class,
                () -> authorizationResponseProcessorService.handleAuthResponse(state, vpToken, "tenant-b"));
        verify(sseEmitterStore).sendValidationFailed(eq(state), eq("TENANT_MISMATCH"), anyString());
        verify(sseEmitterStore, never()).sendValidationFailed(eq(state), eq("INVALID_STATE"), anyString());
        verify(oAuth2AuthorizationService, never()).save(any());
        verifyNoInteractions(vpService, sdJwtVerificationService);
    }

    @Test
    void handleAuthResponse_walletWithoutTenantForTenantBoundLogin_rejects() throws JOSEException {
        // Given
        String state = "state-no-tenant";
        String vpToken = createVpToken("n");
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(tenantBoundRequest(state, "n", "tenant-a"));

        // When / Then
        assertThrows(LoginTenantMismatchException.class,
                () -> authorizationResponseProcessorService.handleAuthResponse(state, vpToken, null));
        verify(oAuth2AuthorizationService, never()).save(any());
    }

    @Test
    void handleAuthResponse_sameTenant_issuesCodeUsingNonceFromCachedRequest() throws JOSEException {
        // Given
        String state = "state-same-tenant";
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(tenantBoundRequest(state, "vp-n", "tenant-a"));
        when(credentialSchemaDispatcher.dispatch(any())).thenReturn(
                DispatchDecision.permitted("test-config-id", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
        when(registeredClientRepository.findByClientId("client-id")).thenReturn(RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build());

        // When
        AuthResponseResult result = authorizationResponseProcessorService.handleAuthResponse(
                state, createVpToken("vp-n"), "tenant-a");

        // Then
        assertNotNull(result.authorizationCode());
        verify(oAuth2AuthorizationService).save(any(OAuth2Authorization.class));
    }

    @Test
    void handleAuthResponse_vpNonceNotFromThisLogin_rejected() throws JOSEException {
        // Given: the VP carries a nonce other than the one cached with this login's request
        String state = "state-other-nonce";
        String vpToken = createVpToken("attacker-n");
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(tenantBoundRequest(state, "vp-n", "tenant-a"));

        // When / Then
        JWTClaimMissingException e = assertThrows(JWTClaimMissingException.class,
                () -> authorizationResponseProcessorService.handleAuthResponse(state, vpToken, "tenant-a"));
        assertEquals("VP nonce does not match the cached nonce for the given state.", e.getMessage());
        verify(oAuth2AuthorizationService, never()).save(any());
    }
}
