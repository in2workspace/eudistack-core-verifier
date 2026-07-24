package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.oauth2.domain.exception.InvalidProofOfPossessionException;
import es.in2.vcverifier.oauth2.domain.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private static final String AUDIT_OUTCOME_REJECT = "REJECT";
    private static final String AUDIT_REASON_CREDENTIAL_TYPE_NOT_ELIGIBLE = "credential_type_not_eligible";
    private static final String AUDIT_REASON_INVALID_PROOF_OF_POSSESSION = "invalid_proof_of_possession";
    private static final String AUDIT_REASON_ISSUER_NOT_TRUSTED = "issuer_not_trusted";
    private static final String AUDIT_REASON_CREDENTIAL_EXPIRED = "credential_expired";
    private static final String AUDIT_REASON_CREDENTIAL_NOT_ACTIVE = "credential_not_active";
    private static final String AUDIT_REASON_CREDENTIAL_REVOKED = "credential_revoked";
    private static final String AUDIT_REASON_EXTERNAL_DEPENDENCY_FAILURE = "external_dependency_failure";
    private static final String AUDIT_REASON_CREDENTIAL_VALIDATION_FAILED = "credential_validation_failed";

    private final ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;
    private final OAuth2M2MAuditPort oAuth2M2MAuditPort;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");
        MultiValueMap<String, String> parameters = getParameters(request);
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
        if (grantType == null) {
            throw new UnsupportedGrantTypeException("The grant_type parameter is required");
        }
        return switch (grantType) {
            case "authorization_code" -> handleAuthorizationCodeGrant(parameters);
            case "client_credentials" -> handleClientCredentialsGrant(parameters);
            case "refresh_token" -> handleRefreshTokenGrant(parameters);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };
    }

    private Authentication handleAuthorizationCodeGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleAuthorizationCodeGrant -- INIT");

        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        String codeVerifier = parameters.getFirst(PkceParameterNames.CODE_VERIFIER);

        String codePrefix = code == null ? "null" : code.substring(0, Math.min(10, code.length()));
        log.info("[AUTH_CODE] codePrefix={}, clientId={}, redirectUriPresent={}, statePresent={}, pkcePresent={}",
                codePrefix, clientId,
                redirectUri != null && !redirectUri.isBlank(),
                state != null && !state.isBlank(),
                codeVerifier != null && !codeVerifier.isBlank());

        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);
        if (authorizationCodeData == null) {
            log.error("[AUTH_CODE] AuthorizationCodeData NOT FOUND for codePrefix={}", codePrefix);
            throw new IllegalArgumentException("Invalid or expired authorization code");
        }

        log.info("[AUTH_CODE] Stored data: statePresent={}, noncePresent={}, scopes={}",
                authorizationCodeData.state() != null && !authorizationCodeData.state().isBlank(),
                authorizationCodeData.clientNonce() != null && !authorizationCodeData.clientNonce().isBlank(),
                authorizationCodeData.requestedScopes());

        if (state != null && !state.isBlank() && (!authorizationCodeData.state().equals(state))) {
            log.error("State mismatch. Expected: {}, Actual: {}", authorizationCodeData.state(), state);
            throw new IllegalArgumentException("Invalid state parameter");
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", authorizationCodeData.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", authorizationCodeData.requestedScopes()));
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, clientId);

        String nonce = authorizationCodeData.clientNonce();
        if (nonce != null && !nonce.isBlank()) {
            additionalParameters.put(NONCE, nonce);
        }
        if (codeVerifier != null && !codeVerifier.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
        }

        log.info("Authorization code grant successfully handled");
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
    }

    private Authentication handleClientCredentialsGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleClientCredentialsGrant -- INIT");
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String clientAssertion = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);

        // Delegate full M2M validation to the workflow (VP/VC parsing, schema, issuer trust,
        // revocation, signature and grant-eligibility checks). ES-02: none of this may propagate
        // as a raw domain exception past the token endpoint — every path below is translated to
        // a standard OAuth2 error.
        // Every branch below logs the full internal cause (exception type + e.getMessage()) for
        // diagnostics/audit, but the OAuth2 error returned to the client carries only the error
        // code (via OAuth2AuthenticationException(String errorCode) -> OAuth2Error(errorCode, null,
        // null)) — no description/uri, so the internal cause never reaches the HTTP response.
        JsonNode vc;
        try {
            vc = clientCredentialsValidationWorkflow.validateClientCredentialsGrant(clientId, clientAssertion);
        } catch (InvalidCredentialTypeException e) {
            log.warn("M2M client '{}' rejected: credential type not eligible for client_credentials: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_CREDENTIAL_TYPE_NOT_ELIGIBLE);
            throw OAuth2ErrorTranslator.invalidClient();
        } catch (InvalidProofOfPossessionException e) {
            log.warn("M2M client '{}' rejected: invalid proof of possession: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_INVALID_PROOF_OF_POSSESSION);
            throw OAuth2ErrorTranslator.invalidClient();
        } catch (IssuerNotAuthorizedException e) {
            log.warn("M2M client '{}' rejected: issuer not trusted: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_ISSUER_NOT_TRUSTED);
            throw OAuth2ErrorTranslator.invalidClient();
        } catch (CredentialExpiredException e) {
            // The credential's temporal validity is what's wrong here, not the client's identity —
            // same RFC 6749 wording used for expired/revoked grants elsewhere.
            log.warn("M2M client '{}' rejected: credential expired: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_CREDENTIAL_EXPIRED);
            throw OAuth2ErrorTranslator.invalidGrant();
        } catch (CredentialNotActiveException e) {
            log.warn("M2M client '{}' rejected: credential not yet active: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_CREDENTIAL_NOT_ACTIVE);
            throw OAuth2ErrorTranslator.invalidGrant();
        } catch (CredentialRevokedException e) {
            log.warn("M2M client '{}' rejected: credential revoked: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_CREDENTIAL_REVOKED);
            throw OAuth2ErrorTranslator.invalidGrant();
        } catch (FailedCommunicationException | StatusListCredentialException e) {
            // Failure talking to an external dependency (trusted-issuers registry, status list) —
            // not the client's fault, so invalid_client/invalid_grant would be misleading.
            log.error("M2M client '{}' validation failed due to an infrastructure error: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_EXTERNAL_DEPENDENCY_FAILURE);
            throw OAuth2ErrorTranslator.serverError();
        } catch (RuntimeException e) {
            // Fail-closed default: everything else thrown by the validation pipeline (malformed VP/VC,
            // untrusted issuer, JWT parsing/verification/claim errors, unsupported credential format,
            // cryptographic binding failures, etc.) means the presented credential could not be used to
            // authenticate this client. Also the safety net for exception types not explicitly enumerated
            // above, so nothing escapes this boundary untranslated.
            log.warn("M2M client '{}' rejected: {}", clientId, e.getMessage());
            publishAudit(clientId, AUDIT_REASON_CREDENTIAL_VALIDATION_FAILED);
            throw OAuth2ErrorTranslator.invalidClient();
        }

        log.info("VP Token validated successfully");
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", vc);
        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, additionalParameters);
    }

    /**
     * Tenant is always published as null here: the credential is only parsed and its mandator
     * organizationIdentifier extracted deep inside validateClientCredentialsGrant, so on every
     * exception path in this method the workflow has already failed before returning a parsed
     * credential — there is nothing in scope to derive a tenant from. (Once a grant succeeds, the
     * accepted credential's tenant is derived and audited downstream in CustomAuthenticationProvider.)
     */
    private void publishAudit(String clientId, String reason) {
        oAuth2M2MAuditPort.publish(OAuth2M2MAuditEvent.builder()
                .clientId(clientId)
                .tenant(null)
                .outcome(AUDIT_OUTCOME_REJECT)
                .reason(reason)
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .build());
    }

    private Authentication handleRefreshTokenGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleRefreshTokenGrant -- INIT");

        String refreshTokenValue = parameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);

        RefreshTokenDataCache refreshTokenDataCache = refreshTokenDataCacheCacheStore.get(refreshTokenValue);
        if (refreshTokenDataCache == null) {
            log.error("Refresh token not found or expired");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        // SEC-F10: Invalidate used refresh token immediately (one-time use / rotation).
        refreshTokenDataCacheCacheStore.delete(refreshTokenValue);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", refreshTokenDataCache.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, clientId);
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        log.info("Refresh token grant successfully handled");
        return new OAuth2RefreshTokenAuthenticationToken(refreshTokenValue, clientPrincipal, null, additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
