package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
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
import java.util.List;
import java.util.Map;
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

    @Override
    public void handleAuthResponse(String state, String vpToken){
        log.info("Processing authorization response");

        // Validate if the state exists in the cache
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);

        // Remove the state from cache after retrieving the Object
        cacheStoreForOAuth2AuthorizationRequest.delete(state);

        Instant issueTime = Instant.now();

        Object expirationLoginValue = oAuth2AuthorizationRequest.getAdditionalParameters().get(EXPIRATION);

        if(expirationLoginValue==null){
            throw new LoginTimeoutException("Start time is missing from login request");
        }

        if (issueTime.getEpochSecond() >= (long) expirationLoginValue) {
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
            validateSdJwtRevocationStatus(result.resolvedClaims());
        } else {
            // JWT VP path (existing logic, unchanged)
            validateVpTokenNonceAndAudience(resolvedVpToken, state);
            try {
                vpService.verifyVerifiablePresentation(resolvedVpToken);
            } catch (Exception e) {
                log.error("VP Token is invalid - VP Token used in H2M flow is invalid: {}", e.getMessage(), e);
                throw e;
            }
            credentialJson = vpService.extractCredentialFromVerifiablePresentationAsJsonNode(resolvedVpToken);
            log.info("JWT VP Token validated successfully");
        }

        // Generate a code (code)
        String code = UUID.randomUUID().toString();
        log.info("Code generated: {}", code);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(oAuth2AuthorizationRequest.getClientId());

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }


        var addl = oAuth2AuthorizationRequest.getAdditionalParameters();
        String codeChallenge       = (String) addl.get(PkceParameterNames.CODE_CHALLENGE);
        String codeChallengeMethod = (String) addl.get(PkceParameterNames.CODE_CHALLENGE_METHOD);


        Instant expirationTime = issueTime.plus(backendConfig.getAccessTokenExpirationSeconds(), ChronoUnit.SECONDS);
        // Register the Oauth2Authorization because is needed for verifications
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode(code, issueTime, expirationTime))
                .attribute(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
                .attribute(OAuth2ParameterNames.REDIRECT_URI, oAuth2AuthorizationRequest.getRedirectUri())
                .attribute(OAuth2ParameterNames.SCOPE, String.join(" ", oAuth2AuthorizationRequest.getScopes()))
                .attribute(OAuth2AuthorizationRequest.class.getName(), oAuth2AuthorizationRequest);

        if (org.springframework.util.StringUtils.hasText(codeChallenge)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        if (org.springframework.util.StringUtils.hasText(codeChallengeMethod)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }

        OAuth2Authorization authorization = authBuilder.build();
        oAuth2AuthorizationService.save(authorization);

        log.info("OAuth2Authorization generated");

        // Retrieve nonce from additional parameters
        String nonceValue = (String) oAuth2AuthorizationRequest.getAdditionalParameters().get(NONCE);

        // Create a builder
        AuthorizationCodeData.AuthorizationCodeDataBuilder authCodeDataBuilder = AuthorizationCodeData.builder()
                .state(state)
                .verifiableCredential(credentialJson)
                .oAuth2Authorization(authorization)
                .requestedScopes(oAuth2AuthorizationRequest.getScopes());

        authCodeDataBuilder.clientNonce(nonceValue);

        // Finally build the object
        AuthorizationCodeData authorizationCodeData = authCodeDataBuilder.build();
        cacheStoreForAuthorizationCodeData.add(code, authorizationCodeData);


        // Build the redirect URL with the code (code) and the state
        String redirectUrl = UriComponentsBuilder.fromHttpUrl(redirectUri)
                .queryParam("code", code)
                .queryParam("state", state)
                .build()
                .toUriString();

        //Perform the redirection using HttpServletResponse
        log.info("Redirecting to URL: {}", redirectUrl);

        // Send the redirect URL to the browser via SSE
        sseEmitterStore.send(state, redirectUrl);

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

        if (verifier == null) {
            log.warn("No CredentialStatusVerifier registered for TokenStatusListEntry; skipping revocation check");
            return;
        }

        try {
            boolean revoked = verifier.isRevoked(uri, idx, "revocation");
            if (revoked) {
                throw new CredentialRevokedException("SD-JWT credential is revoked (Token Status List uri=" + uri + ", idx=" + idx + ")");
            }
            log.info("SD-JWT credential is not revoked");
        } catch (CredentialRevokedException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Could not verify SD-JWT credential revocation status. " +
                    "Token Status List may be unreachable. Proceeding with presentation. Error: {}",
                    e.getMessage());
        }
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