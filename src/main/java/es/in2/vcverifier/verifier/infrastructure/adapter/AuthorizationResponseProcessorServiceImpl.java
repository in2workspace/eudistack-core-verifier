package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationLoggerPort;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationService;
import es.in2.vcverifier.verifier.domain.service.VpService;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

import static es.in2.vcverifier.shared.domain.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationResponseProcessorServiceImpl implements AuthorizationResponseProcessorService {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final VpService vpService;
    private final SdJwtVerificationService sdJwtVerificationService;
    private final ObjectMapper objectMapper;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final SseEmitterStore sseEmitterStore;
    private final BackendConfig backendConfig;
    private final CacheStore<String> cacheForNonceByState;
    private final CryptoComponent cryptoComponent;
    private final List<CredentialStatusVerifier> credentialStatusVerifiers;
    private final CredentialSchemaDispatcher credentialSchemaDispatcher;
    private final CredentialVerificationLoggerPort credentialVerificationLogger;

    @Override
    public JsonNode handleAuthResponse(String state, String vpToken){
        log.info("Processing authorization response");

        boolean verificationLogged = false;
        String configurationId = null;
        Throwable verificationFailure = null;

        try {
            // Validate if the state exists in the cache
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);

            // Remove the state from cache after retrieving the Object
            cacheStoreForOAuth2AuthorizationRequest.delete(state);

            Instant issueTime = Instant.now();

            Object expirationLoginValue = oAuth2AuthorizationRequest.getAdditionalParameters().get(EXPIRATION);

            if(expirationLoginValue==null){
                sseEmitterStore.sendValidationFailed(state, "INVALID_REQUEST", "Start time is missing from login request");
                throw new LoginTimeoutException("Start time is missing from login request");
            }

            if (issueTime.getEpochSecond() >= (long) expirationLoginValue) {
                sseEmitterStore.sendValidationFailed(state, "LOGIN_TIMEOUT", "Login time has expired");
                throw new LoginTimeoutException("Login time has expired");
            }
            String redirectUri = oAuth2AuthorizationRequest.getRedirectUri();
            // Decode vpToken from Base64
            String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);

            // Detect DCQL format (JSON object) vs legacy format (direct JWT/SD-JWT string)
            String resolvedVpToken = extractVpTokenFromPossibleDcql(decodedVpToken);

            log.info("Decoded VP Token (format={})", isSdJwt(resolvedVpToken) ? "sd-jwt" : "jwt");

            // Validate and extract credential based on format
            JsonNode credentialJson;
            try {
                if (isSdJwt(resolvedVpToken)) {
                    // SD-JWT VC path: nonce/aud validation is done inside KB-JWT verification
                    // OID4VP Final 1.0: aud MUST be client_id. Use DID key as primary expected audience.
                    String cachedNonce = cacheForNonceByState.get(state);
                    String expectedAud = cryptoComponent.getClientId();
                    SdJwtVerificationResult result = sdJwtVerificationService.verifyPresentation(
                            resolvedVpToken, expectedAud, cachedNonce);
                    credentialJson = objectMapper.valueToTree(result.resolvedClaims());
                    log.info("SD-JWT VC validated successfully. vct={}", result.vct());

                    // Check revocation via Token Status List (status.status_list)
                    try {
                        validateSdJwtRevocationStatus(result.resolvedClaims());
                    } catch (CredentialRevokedException e) {
                        sseEmitterStore.sendValidationFailed(state, "CREDENTIAL_REVOKED", "The credential has been revoked");
                        throw e;
                    }
                } else {
                    // JWT VP path
                    validateVpTokenNonceAndAudience(resolvedVpToken, state);
                    try {
                        vpService.verifyVerifiablePresentation(resolvedVpToken);
                    } catch (CredentialRevokedException e) {
                        sseEmitterStore.sendValidationFailed(state, "CREDENTIAL_REVOKED", "The credential has been revoked");
                        throw e;
                    }
                    credentialJson = vpService.extractCredentialFromVerifiablePresentationAsJsonNode(resolvedVpToken);
                    log.info("JWT VP Token validated successfully");
                }
            } catch (CredentialRevokedException e) {
                throw e;
            } catch (JWTVerificationException e) {
                sseEmitterStore.sendValidationFailed(state, "SIGNATURE_INVALID", "VP signature verification failed: " + e.getMessage());
                throw e;
            } catch (Exception e) {
                sseEmitterStore.sendValidationFailed(state, "VALIDATION_ERROR", "VP validation failed: " + e.getMessage());
                throw e;
            }

            try {
                DispatchDecision dispatchDecision = credentialSchemaDispatcher.dispatch(credentialJson);
                configurationId = dispatchDecision.credentialConfigurationId();
            } catch (LegacyFormatSunsetClosedException | BumpedFormatTemporarilyDisabledException
                     | UnknownCredentialFormatException e) {
                sseEmitterStore.sendValidationFailed(state, "FORMAT_GATED", e.getMessage());
                throw e;
            }

            verificationLogged = true;
            credentialVerificationLogger.logVerifiedOk(configurationId);

            // Generate a code (code)
            // SEC-S9: Authorization codes must not be logged in full.
            String code = UUID.randomUUID().toString();
            log.info("Authorization code generated: {}...", code.substring(0, 8));

            RegisteredClient registeredClient = registeredClientRepository.findByClientId(oAuth2AuthorizationRequest.getClientId());

            if (registeredClient == null) {
                sseEmitterStore.sendValidationFailed(state, "UNAUTHORIZED_CLIENT", "Client not found or not authorized");
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }

            var addl = oAuth2AuthorizationRequest.getAdditionalParameters();
            String codeChallenge       = (String) addl.get(PkceParameterNames.CODE_CHALLENGE);
            String codeChallengeMethod = (String) addl.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            String nonceValue = (String) addl.get(NONCE);

            String redirectUrl = issueAuthorizationCode(
                    registeredClient,
                    redirectUri,
                    oAuth2AuthorizationRequest.getScopes(),
                    state,
                    codeChallenge,
                    codeChallengeMethod,
                    nonceValue,
                    credentialJson
            );

            // SEC-O2: Log redirect target without full authorization code.
            log.info("Redirecting to: {}", redirectUri);

            // Send the redirect URL to the browser via SSE
            sseEmitterStore.send(state, redirectUrl);

            return credentialJson;

        } catch (NoSuchElementException e) {
            // State not found in cache (expired or invalid)
            log.error("State not found or expired: {}", state);
            sseEmitterStore.sendValidationFailed(state, "INVALID_STATE", "State not found or expired");
            verificationFailure = e;
            throw e;
        } catch (CredentialExpiredException e) {
            log.error("Credential has expired: {}", e.getMessage());
            sseEmitterStore.sendValidationFailed(state, "CREDENTIAL_EXPIRED", "The credential has expired");
            verificationFailure = e;
            throw e;
        } catch (CredentialNotActiveException e) {
            log.error("Credential not yet active: {}", e.getMessage());
            sseEmitterStore.sendValidationFailed(state, "CREDENTIAL_NOT_ACTIVE", "The credential is not yet active");
            verificationFailure = e;
            throw e;
        } catch (IssuerNotAuthorizedException e) {
            log.error("Issuer not authorized: {}", e.getMessage());
            sseEmitterStore.sendValidationFailed(state, "ISSUER_NOT_TRUSTED", "The credential issuer is not trusted");
            verificationFailure = e;
            throw e;
        } catch (LoginTimeoutException | CredentialRevokedException | JWTVerificationException | OAuth2AuthenticationException
                 | LegacyFormatSunsetClosedException | BumpedFormatTemporarilyDisabledException | UnknownCredentialFormatException e) {
            // Already sent SSE event in inner catch blocks, just re-throw
            verificationFailure = e;
            throw e;
        } catch (Exception e) {
            // Catch-all for unexpected errors
            log.error("Unexpected error during VP validation: {}", e.getMessage(), e);
            sseEmitterStore.sendValidationFailed(state, "VALIDATION_ERROR", "Validation failed: " + e.getMessage());
            verificationFailure = e;
            throw e;
        } finally {
            if (!verificationLogged) {
                credentialVerificationLogger.logVerifiedError(configurationId, verificationFailure);
            }
        }
    }

    @Override
    public String issueCodeForReusedSession(
            String clientId,
            String redirectUri,
            Set<String> scopes,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce,
            JsonNode credentialJson
    ) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        String redirectUrl = issueAuthorizationCode(
                registeredClient, redirectUri, scopes, state, codeChallenge, codeChallengeMethod, nonce, credentialJson);
        log.info("SSO reuse: authorization code issued directly, no VP re-presentation");
        return redirectUrl;
    }

    /**
     * Generates a fresh authorization code, registers the {@link OAuth2Authorization} (needed at
     * the token endpoint), caches the {@link AuthorizationCodeData} for {@code TokenGenerationWorkflow}
     * to read the credential claims from, and builds the {@code redirectUri?code=...&state=...} URL.
     * Shared by the VP-validated establishment path ({@link #handleAuthResponse}) and the SSO-reuse
     * path ({@link #issueCodeForReusedSession}) — the only difference between them is where
     * {@code credentialJson} comes from (freshly verified VP vs. cached establishment snapshot).
     */
    private String issueAuthorizationCode(
            RegisteredClient registeredClient,
            String redirectUri,
            Set<String> scopes,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce,
            JsonNode credentialJson
    ) {
        Instant issueTime = Instant.now();

        // SEC-S9: Authorization codes must not be logged in full.
        String code = UUID.randomUUID().toString();
        log.info("Authorization code generated: {}...", code.substring(0, 8));

        Instant expirationTime = issueTime.plus(backendConfig.getAccessTokenExpirationSeconds(), ChronoUnit.SECONDS);

        // Spring Authorization Server's OWN stock OAuth2AuthorizationCodeAuthenticationProvider
        // (still in the token-endpoint provider chain alongside CustomAuthenticationProvider) runs
        // its internal CodeVerifierAuthenticator on every authorization_code grant for a PKCE client,
        // and that reads this attribute directly off the OAuth2Authorization — NOT just the
        // codeChallenge/codeChallengeMethod attributes above (those are for CustomAuthenticationProvider's
        // own check). Omitting it throws a raw NPE deep inside Spring's PKCE validator instead of a
        // clean OAuth2 error, for every single authorization_code exchange, not just SSO reuse.
        Map<String, Object> requestAdditionalParameters = new HashMap<>();
        if (org.springframework.util.StringUtils.hasText(nonce)) {
            requestAdditionalParameters.put(NONCE, nonce);
        }
        if (org.springframework.util.StringUtils.hasText(codeChallenge)) {
            requestAdditionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        if (org.springframework.util.StringUtils.hasText(codeChallengeMethod)) {
            requestAdditionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(backendConfig.getUrl())
                .clientId(registeredClient.getClientId())
                .redirectUri(redirectUri)
                .scopes(scopes)
                .state(state)
                .additionalParameters(requestAdditionalParameters)
                .build();

        // A unique id per authorization, NOT registeredClient.getId(): that static value is the
        // same for every login of this client, so InMemoryOAuth2AuthorizationService.save() would
        // overwrite one login's code/attributes every time another concurrent login (or SSO reuse)
        // of the same client issues its own code — silently breaking the earlier login's exchange.
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(UUID.randomUUID().toString())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode(code, issueTime, expirationTime))
                .attribute(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
                .attribute(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                .attribute(OAuth2ParameterNames.SCOPE, String.join(" ", scopes))
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

        if (org.springframework.util.StringUtils.hasText(codeChallenge)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        if (org.springframework.util.StringUtils.hasText(codeChallengeMethod)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }

        OAuth2Authorization authorization = authBuilder.build();
        oAuth2AuthorizationService.save(authorization);

        log.info("OAuth2Authorization generated");

        AuthorizationCodeData.AuthorizationCodeDataBuilder authCodeDataBuilder = AuthorizationCodeData.builder()
                .state(state)
                .verifiableCredential(credentialJson)
                .oAuth2Authorization(authorization)
                .requestedScopes(scopes)
                .clientNonce(nonce);

        cacheStoreForAuthorizationCodeData.add(code, authCodeDataBuilder.build());

        return UriComponentsBuilder.fromHttpUrl(redirectUri)
                .queryParam("code", code)
                .queryParam("state", state)
                .build()
                .toUriString();
    }

    private boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    /**
     * Extracts the VP token from a possible DCQL format.
     * DCQL vp_token is a JSON object keyed by credential query IDs, e.g.:
     * { "lear_jwt_vc": ["eyJ..."] }
     * Legacy vp_token is a direct JWT or SD-JWT string.
     */
    private String extractVpTokenFromPossibleDcql(String decoded) {
        String trimmed = decoded.trim();
        if (trimmed.startsWith("{")) {
            try {
                JsonNode dcqlVpToken = objectMapper.readTree(trimmed);
                // Iterate entries and take the first VP token found
                var fields = dcqlVpToken.fields();
                while (fields.hasNext()) {
                    var entry = fields.next();
                    JsonNode value = entry.getValue();
                    if (value.isArray() && !value.isEmpty()) {
                        String token = value.get(0).asText();
                        log.info("Extracted VP token from DCQL format, credential query id: {}", entry.getKey());
                        return token;
                    } else if (value.isTextual()) {
                        log.info("Extracted VP token from DCQL format, credential query id: {}", entry.getKey());
                        return value.asText();
                    }
                }
                throw new JWTParsingException("DCQL vp_token JSON object contains no entries");
            } catch (Exception e) {
                if (e instanceof JWTParsingException) throw (JWTParsingException) e;
                throw new JWTParsingException("Failed to parse DCQL vp_token: " + e.getMessage());
            }
        }
        // Legacy format: direct JWT or SD-JWT string
        return trimmed;
    }

    /**
     * Validates revocation status for SD-JWT credentials using Token Status List.
     * SD-JWT credentials embed status as: { "status": { "status_list": { "uri": "...", "idx": N } } }
     * Non-blocking: if the status list endpoint is unreachable, log a warning and proceed.
     */
    @SuppressWarnings("unchecked")
    private void validateSdJwtRevocationStatus(Map<String, Object> resolvedClaims) {
        Object statusObj = resolvedClaims.get("status");
        if (!(statusObj instanceof Map<?, ?> statusMap)) {
            log.debug("No 'status' block in SD-JWT claims; skipping revocation check");
            return;
        }

        Object statusListObj = statusMap.get("status_list");
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) {
            log.debug("No 'status_list' in status block; skipping revocation check");
            return;
        }

        String uri = statusListMap.get("uri") instanceof String s ? s : null;
        Object idxObj = statusListMap.get("idx");
        String idx = idxObj != null ? String.valueOf(idxObj) : null;

        if (uri == null || uri.isBlank() || idx == null) {
            log.debug("Incomplete status_list (uri={}, idx={}); skipping revocation check", uri, idx);
            return;
        }

        log.debug("Token Status List detected: uri={}, idx={}", uri, idx);

        CredentialStatusVerifier verifier = credentialStatusVerifiers.stream()
                .filter(v -> v.supports("TokenStatusListEntry"))
                .findFirst()
                .orElse(null);

        // SEC-O3: Fail-closed — reject if no verifier is available for revocation check.
        if (verifier == null) {
            throw new CredentialRevokedException(
                    "Cannot verify SD-JWT revocation: no CredentialStatusVerifier registered for TokenStatusListEntry");
        }

        // SEC-S2: Fail-closed — if revocation status cannot be determined, reject the credential.
        boolean revoked = verifier.isRevoked(uri, idx, "revocation");
        if (revoked) {
            throw new CredentialRevokedException("SD-JWT credential is revoked (Token Status List uri=" + uri + ", idx=" + idx + ")");
        }
        log.info("SD-JWT credential is not revoked");
    }

    private void validateVpTokenNonceAndAudience(String decodedVpToken, String state) {
        if (state == null || state.isBlank()) {
            throw new JWTClaimMissingException("The 'state' claim is missing in the VP token.");
        }
        try {
            SignedJWT vpSignedJWT = SignedJWT.parse(decodedVpToken);
            String vpNonce = vpSignedJWT.getJWTClaimsSet().getClaim(NONCE).toString();
            if (vpNonce == null || vpNonce.isBlank()) {
                throw new JWTClaimMissingException("The 'nonce' claim is missing in the VP token.");
            }
            String cachedNonce = cacheForNonceByState.get(state);
            if (cachedNonce == null) {
                throw new JWTClaimMissingException("No nonce found in cache for state=" + state);
            }
            if (!vpNonce.equals(cachedNonce)) {
                throw new JWTClaimMissingException("VP nonce does not match the cached nonce for the given state.");
            }
            List<String> audiences = vpSignedJWT.getJWTClaimsSet().getAudience();
            if (audiences == null || audiences.isEmpty()) {
                throw new JWTClaimMissingException("The 'aud' claim is missing in the VP token.");
            }
            // OID4VP Final 1.0: aud MUST be client_id. Accept both x509_hash/DID client_id and backend URL for backwards compatibility.
            String expectedClientId = cryptoComponent.getClientId();
            String expectedUrl = backendConfig.getUrl();
            log.debug("VP aud validation: expectedClientId={}, expectedUrl={}, received={}", expectedClientId, expectedUrl, audiences);
            if (!audiences.contains(expectedClientId) && !audiences.contains(expectedUrl)) {
                throw new JWTClaimMissingException("The 'aud' claim in the VP token does not match the verifier client_id or URL.");
            }
            log.debug("Validated VP nonce: received={}, cached={}, audience={}", vpNonce, cachedNonce, audiences);
        } catch (ParseException e) {
            throw new JWTParsingException("Failed to parse the VP JWT or extract claims.");
        }
    }

}