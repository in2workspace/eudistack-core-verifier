package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.oauth2.domain.exception.TenantMismatchException;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.*;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private static final String AUDIT_OUTCOME_ACCEPT = "ACCEPT";
    private static final String AUDIT_OUTCOME_REJECT = "REJECT";
    private static final String AUDIT_REASON_TENANT_MISMATCH = "tenant_mismatch";
    private static final String AUDIT_REASON_TENANT_NOT_DERIVABLE = "tenant_not_derivable";
    private static final String AUDIT_REASON_REQUEST_TENANT_NOT_DERIVABLE = "request_tenant_not_derivable";

    private final RegisteredClientRepository registeredClientRepository;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final TokenGenerationWorkflow tokenGenerationWorkflow;
    private final SchemaProfileRegistry schemaProfileRegistry;
    private final OAuth2M2MAuditPort oAuth2M2MAuditPort;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationGrantAuthenticationToken oAuth2AuthorizationGrantAuthenticationToken) {
            log.debug("Authorization token received: {}", oAuth2AuthorizationGrantAuthenticationToken);
            return handleGrant(oAuth2AuthorizationGrantAuthenticationToken);
        }
        log.error("Unsupported grant type: {}", authentication.getClass().getName());
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleGrant(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        log.info("Processing authorization grant");

        String clientId = getClientId(authentication);
        boolean isM2M = authentication instanceof OAuth2ClientCredentialsAuthenticationToken;
        RegisteredClient registeredClient;
        if (isM2M) {
            try {
                registeredClient = getOrBuildRegisteredClient(clientId, authentication);
            } catch (TenantMismatchException e) {
                log.warn("M2M client '{}' rejected: {}", clientId, e.getMessage());
                throw OAuth2ErrorTranslator.invalidClient();
            }
        } else {
            registeredClient = getRegisteredClient(clientId);
        }

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            if (isPublicPkceClient(registeredClient)) {
                validateAuthorizationCodePkce(authCodeToken, clientId);
            } else {
                log.debug("Omitting redirect+PKCE validation for confidential client '{}'", clientId);
            }
        }

        JsonNode credentialJson = getJsonCredential(authentication);

        // Resolve audience
        String audience;
        if (isM2M) {
            audience = backendConfig.getUrl();
        } else {
            Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
            if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
                audience = additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
            } else {
                // Fallback: check credential type via profile — M2M-eligible credentials use verifier as audience
                String credType = tokenGenerationWorkflow.extractCredentialType(credentialJson);
                boolean isM2MEligible = schemaProfileRegistry.findByConfigId(credType)
                        .map(profile -> profile.grantEligibility().contains("client_credentials"))
                        .orElse(false);
                if (isM2MEligible) {
                    audience = backendConfig.getUrl();
                } else {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
                }
            }
        }

        // Extract tenant from OIDC client registration settings
        Map<String, Object> clientSettings = registeredClient.getClientSettings().getSettings();
        String tenant = clientSettings.containsKey(CLIENT_SETTING_TENANT)
                ? (String) clientSettings.get(CLIENT_SETTING_TENANT)
                : null;

        // Delegate token generation to the workflow
        TokenGenerationWorkflow.Result tokenResult = tokenGenerationWorkflow.issueAccessToken(
                credentialJson, audience, authentication.getAdditionalParameters(), !isM2M, tenant);

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenResult.accessTokenJwt(),
                tokenResult.issueTime(),
                tokenResult.expirationTime()
        );

        OAuth2RefreshToken oAuth2RefreshToken;
        Map<String, Object> additionalParameters;

        if (isM2M) {
            oAuth2RefreshToken = null;
            additionalParameters = Map.of();
        } else {
            additionalParameters = Map.of("id_token", tokenResult.idTokenJwt());
            oAuth2RefreshToken = getOAuth2RefreshToken(authentication, tokenResult, clientId, credentialJson, registeredClient);
        }

        log.info("Authorization grant successfully processed");

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            OAuth2Authorization authToRemove = oAuth2AuthorizationService.findByToken(
                    authCodeToken.getCode(), new OAuth2TokenType(OAuth2ParameterNames.CODE));
            if (authToRemove != null) {
                oAuth2AuthorizationService.remove(authToRemove);
            }
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    // --- Helper methods ---

    private boolean isPublicPkceClient(RegisteredClient rc) {
        if (rc == null) return false;
        boolean isPublic = rc.getClientAuthenticationMethods().size() == 1
                && rc.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);
        boolean requirePkce = rc.getClientSettings() != null && rc.getClientSettings().isRequireProofKey();
        return isPublic && requirePkce;
    }

    private void validateAuthorizationCodePkce(OAuth2AuthorizationCodeAuthenticationToken authCodeToken, String requestedClientId) {
        final String code = authCodeToken.getCode();

        OAuth2Authorization authorization = oAuth2AuthorizationService.findByToken(code, new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorization == null) throw OAuth2ErrorTranslator.invalidGrant();

        String storedClientId = authorization.getAttribute(OAuth2ParameterNames.CLIENT_ID);
        if (!Objects.equals(storedClientId, requestedClientId)) throw OAuth2ErrorTranslator.invalidGrant();

        String storedChallenge = authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE);
        String storedMethod = authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD);

        boolean requirePkce = Optional.ofNullable(registeredClientRepository.findByClientId(storedClientId))
                .map(RegisteredClient::getClientSettings)
                .map(cs -> cs.isRequireProofKey())
                .orElse(false);

        if (!org.springframework.util.StringUtils.hasText(storedChallenge)) {
            if (requirePkce) throw OAuth2ErrorTranslator.invalidGrant();
            return;
        }

        String codeVerifier = (String) authCodeToken.getAdditionalParameters().get(PkceParameterNames.CODE_VERIFIER);
        if (!org.springframework.util.StringUtils.hasText(codeVerifier)) throw OAuth2ErrorTranslator.invalidGrant();

        // SEC-S1: Only S256 is accepted. PLAIN method is rejected per HAIP / RFC 7636 §4.2.
        String method = (storedMethod == null ? "S256" : storedMethod).toUpperCase(Locale.ROOT);
        if (!"S256".equals(method)) {
            log.warn("Rejected PKCE method '{}' — only S256 is allowed", method);
            throw OAuth2ErrorTranslator.invalidGrant();
        }
        if (!s256(codeVerifier).equals(storedChallenge)) throw OAuth2ErrorTranslator.invalidGrant();
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
    }

    private OAuth2RefreshToken getOAuth2RefreshToken(OAuth2AuthorizationGrantAuthenticationToken authentication,
                                                      TokenGenerationWorkflow.Result tokenResult, String clientId,
                                                      JsonNode credentialJson, RegisteredClient registeredClient) {
        OAuth2RefreshToken oAuth2RefreshToken = issueRefreshToken(tokenResult.issueTime());

        RefreshTokenDataCache refreshTokenDataCache = RefreshTokenDataCache.builder()
                .refreshToken(oAuth2RefreshToken)
                .clientId(clientId)
                .verifiableCredential(credentialJson)
                .build();

        cacheStoreForRefreshTokenData.add(oAuth2RefreshToken.getTokenValue(), refreshTokenDataCache);

        // A unique id per authorization, NOT registeredClient.getId(): that static value is the
        // same for every login of this client, so InMemoryOAuth2AuthorizationService.save() would
        // overwrite one tab/session's authorization (and its id_token) every time another tab of
        // the same client (e.g. an SSO reuse) exchanges its own code — silently breaking that
        // earlier tab's later id_token_hint lookup on logout.
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(UUID.randomUUID().toString())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(oAuth2RefreshToken)
                .attribute(Principal.class.getName(), authentication.getPrincipal());

        // EUDISTACK-551: Spring AS's RP-Initiated Logout (/oidc/logout) resolves the id_token_hint
        // via OAuth2AuthorizationService#findByToken(..., ID_TOKEN_TOKEN_TYPE) — without registering
        // the id_token here, every logout attempt fails with invalid_token, no session ever gets
        // invalidated. The id_token itself is still hand-built by TokenGenerationWorkflow (VC-derived
        // claims); this only makes Spring AS aware of it for its own bookkeeping.
        if (tokenResult.idTokenJwt() != null) {
            OidcIdToken oidcIdToken = new OidcIdToken(
                    tokenResult.idTokenJwt(), tokenResult.issueTime(), tokenResult.expirationTime(), tokenResult.idTokenClaims());
            authorizationBuilder.token(oidcIdToken);
        }

        oAuth2AuthorizationService.save(authorizationBuilder.build());
        return oAuth2RefreshToken;
    }

    private String getClientId(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(OAuth2ParameterNames.CLIENT_ID)) {
            return additionalParameters.get(OAuth2ParameterNames.CLIENT_ID).toString();
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        return registeredClient;
    }

    /**
     * For M2M (client_credentials): first tries the registered client repository.
     * If not found, builds a synthetic RegisteredClient from the validated credential,
     * so machines don't need to be pre-registered in clients.yaml.
     */
    private RegisteredClient getOrBuildRegisteredClient(String clientId, OAuth2AuthorizationGrantAuthenticationToken authentication) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient != null) {
            return registeredClient;
        }
        log.info("M2M client '{}' not pre-registered, building synthetic client from credential", clientId);
        JsonNode credentialJson = getJsonCredential(authentication);
        List<String> powerDomains = extractPowerDomainsFromCredential(credentialJson);

        // AD-2 fail-closed: a credential with no mandate.power[].domain cannot be trusted to
        // authorize any tenant, so it is rejected outright rather than falling through with no
        // tenant restriction. (mandator.organizationIdentifier is NOT a tenant identifier — it is
        // the mandator's own real business identifier (e.g. a VAT-style code) checked elsewhere,
        // per the same pattern the Issuer itself uses for tenant-domain authorization checks.)
        if (powerDomains.isEmpty()) {
            publishM2MAudit(clientId, null, AUDIT_OUTCOME_REJECT, AUDIT_REASON_TENANT_NOT_DERIVABLE);
            throw new TenantMismatchException(
                    "Cannot determine credential tenant: missing mandate.power[].domain");
        }

        // AD-2 fail-closed, symmetric case: a request whose tenant cannot be resolved cannot be
        // trusted to isolate anything either, so it is rejected rather than trusting the
        // credential's self-declared tenant unconditionally.
        String requestTenant = resolveCurrentTenant();
        if (requestTenant == null) {
            publishM2MAudit(clientId, String.join(",", powerDomains), AUDIT_OUTCOME_REJECT, AUDIT_REASON_REQUEST_TENANT_NOT_DERIVABLE);
            throw new TenantMismatchException(
                    "Cannot determine request tenant: unable to resolve tenant from request context");
        }
        boolean tenantAuthorized = powerDomains.stream().anyMatch(domain -> domain.equalsIgnoreCase(requestTenant));
        if (!tenantAuthorized) {
            publishM2MAudit(clientId, String.join(",", powerDomains), AUDIT_OUTCOME_REJECT, AUDIT_REASON_TENANT_MISMATCH);
            throw new TenantMismatchException(
                    "Credential power domains " + powerDomains + " do not authorize request tenant '" + requestTenant + "'");

        }
        // Use the request-resolved tenant (already normalized to lowercase by TenantDomainFilter)
        // so client settings, token claims, and audit logs stay consistent regardless of how the
        // credential itself capitalized the power domain.
        String tenant = requestTenant;

        RegisteredClient syntheticClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder().setting(CLIENT_SETTING_TENANT, tenant).build())
                .build();

        publishM2MAudit(clientId, tenant, AUDIT_OUTCOME_ACCEPT, null);
        return syntheticClient;
    }

    /**
     * Reads the tenant resolved by TenantDomainFilter for the current request.
     * Returns null when no request context is available (e.g. in tests without a servlet request).
     */
    private String resolveCurrentTenant() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attributes != null ? TenantDomainFilter.getCurrentTenant(attributes.getRequest()) : null;
        } catch (Exception e) {
            log.debug("Unable to resolve current tenant from request context", e);
            return null;
        }
    }

    private void publishM2MAudit(String clientId, String tenant, String outcome, String reason) {
        oAuth2M2MAuditPort.publish(OAuth2M2MAuditEvent.builder()
                .clientId(clientId)
                .tenant(tenant)
                .outcome(outcome)
                .reason(reason)
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .build());
    }

    /**
     * Extracts the tenant domain(s) this credential's mandate authorizes.
     * Navigates: credentialSubject.mandate.power[].domain
     *
     * mandator.organizationIdentifier is deliberately NOT used here — it carries the mandator's
     * own real-world business identifier (e.g. a VAT-style code), not a tenant slug, and is never
     * equal to one for a genuinely issued credential. mandate.power[].domain is the field the
     * Issuer itself already uses for the equivalent tenant-domain authorization check (see
     * PolicyContextFactory.resolveTenantAdmin in eudistack-core-issuer).
     */
    private List<String> extractPowerDomainsFromCredential(JsonNode credentialJson) {
        JsonNode powers = credentialJson.at("/credentialSubject/mandate/power");
        if (!powers.isArray() || powers.isEmpty()) {
            log.warn("No mandate.power[] found in credential, cannot resolve authorized tenant domain(s)");
            return List.of();
        }
        List<String> domains = new ArrayList<>();
        for (JsonNode power : powers) {
            JsonNode domainNode = power.get("domain");
            if (domainNode != null && !domainNode.isNull() && !domainNode.asText().isBlank()) {
                domains.add(domainNode.asText());
            }
        }
        log.info("Extracted power domain(s) from M2M credential: {}", domains);
        return domains;
    }

    private JsonNode getJsonCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);
    }

    private OAuth2RefreshToken issueRefreshToken(Instant issueTime) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] refreshTokenBytes = new byte[32];
        secureRandom.nextBytes(refreshTokenBytes);
        String refreshTokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshTokenBytes);
        Instant refreshTokenExpirationTime = issueTime.plus(
                backendConfig.getRefreshTokenExpirationSeconds(),
                ChronoUnit.SECONDS
        );
        return new OAuth2RefreshToken(refreshTokenValue, issueTime, refreshTokenExpirationTime);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
