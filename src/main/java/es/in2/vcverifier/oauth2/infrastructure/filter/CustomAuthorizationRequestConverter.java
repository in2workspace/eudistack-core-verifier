package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_ID;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.INTERACTION_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUEST_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUIRED_EXTERNAL_USER_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.util.Constants.SCOPE;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final String SSO_COOKIE_PREFIX = "__Secure-sso-";

    private final DIDService didService;
    private final JWTService jwtService;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final BackendConfig backendConfig;
    private final RegisteredClientRepository registeredClientRepository;
    private final boolean isNonceRequiredOnFapiProfile;
    private final long loginTimeoutSeconds;
    private final HttpClient httpClient;
    private final AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;
    private final SafeUrlValidator safeUrlValidator;
    private final ReuseSsoSessionWorkflow reuseSsoSessionWorkflow;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomAuthorizationRequestConverter.convert");

        String portalUrl = resolvePortalUrlFromRequest(request);
        String originalRequestURL = getFullRequestUrl(request);
        String contextPath = request.getContextPath();

        String requestUri = request.getParameter(REQUEST_URI);
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        String clientNonce = request.getParameter(NONCE);
        String codeChallenge = request.getParameter(PkceParameterNames.CODE_CHALLENGE);
        String codeChallengeMethod = request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD);
        AuthorizationContext authorizationContext = AuthorizationContext.builder()
                .requestUri(requestUri)
                .state(state)
                .originalRequestURL(originalRequestURL)
                .redirectUri(redirectUri)
                .clientNonce(clientNonce)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .scope(scope)
                .portalUrl(portalUrl)
                .contextPath(contextPath)
                .build();

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Unauthorized client: Client with ID {} not found.", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Case 1: Standard OIDC authorization request without a signed JWT object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            ReuseSsoSessionWorkflow.Result ssoResult = tryReuseSsoSession(request, authorizationContext, clientId);
            if (ssoResult != null) {
                handlePromptNoneResult(ssoResult.status(), authorizationContext);
            }
            return handleOIDCStandardRequest(authorizationContext, registeredClient);
        }

        // Case 2: FAPI authorization request with a signed JWT object
        return handleFAPIRequest(authorizationContext, request, registeredClient);
    }

    /**
     * When prompt=none is present, runs the SSO session reuse workflow and returns its result.
     * Returns null when prompt != none so the caller skips OIDC error handling entirely.
     */
    private ReuseSsoSessionWorkflow.Result tryReuseSsoSession(HttpServletRequest request,
                                                              AuthorizationContext ctx,
                                                              String clientId) {
        if (!"none".equals(request.getParameter("prompt"))) {
            return null;
        }
        String tenant = TenantDomainFilter.getCurrentTenant(request);
        if (tenant == null || tenant.isBlank()) {
            return null;
        }
        String cookieValue = extractCookieValue(request, SSO_COOKIE_PREFIX + tenant);
        return reuseSsoSessionWorkflow.reuse(tenant, cookieValue, ctx, clientId);
    }

    /**
     * Handles the result of the SSO session reuse workflow for prompt=none requests.
     * LOGIN_REQUIRED and INTERACTION_REQUIRED redirect to the client's redirect_uri with the
     * corresponding OIDC error code as required by the spec (RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6).
     * ALLOWED falls through so the caller continues; direct code issuance is a separate story.
     */
    private void handlePromptNoneResult(ReuseSsoSessionWorkflow.Result.Status status,
                                        AuthorizationContext ctx) {
        switch (status) {
            case LOGIN_REQUIRED -> throwPromptNoneOidcError(LOGIN_REQUIRED, ctx);
            case INTERACTION_REQUIRED -> throwPromptNoneOidcError(INTERACTION_REQUIRED, ctx);
            default -> { /* ALLOWED: fall through to standard flow */ }
        }
    }

    private void throwPromptNoneOidcError(String errorCode, AuthorizationContext ctx) {
        String location = ctx.redirectUri() + "?error=" + errorCode
                + (ctx.state() != null && !ctx.state().isBlank()
                   ? "&state=" + URLEncoder.encode(ctx.state(), StandardCharsets.UTF_8)
                   : "");
        OAuth2Error error = new OAuth2Error(errorCode, null, location);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    private String extractCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private Authentication handleFAPIRequest(AuthorizationContext authorizationContext,
                                             HttpServletRequest request,
                                             RegisteredClient registeredClient) {
        String jwt = retrieveJwtFromRequestUriOrRequest(
                authorizationContext.requestUri(), request, registeredClient, authorizationContext.originalRequestURL(),
                authorizationContext.portalUrl(), authorizationContext.contextPath());

        SignedJWT signedJwt = jwtService.parseJWT(jwt);

        validateOAuth2Parameters(registeredClient, authorizationContext.scope(), signedJwt,
                authorizationContext.originalRequestURL(), authorizationContext.portalUrl(), authorizationContext.contextPath());
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), signedJwt,
                authorizationContext.originalRequestURL(), authorizationContext.portalUrl(), authorizationContext.contextPath());

        if (isNonceRequiredOnFapiProfile) {
            validateNonceRequired(authorizationContext.clientNonce(), registeredClient,
                    authorizationContext.originalRequestURL(), authorizationContext.portalUrl(), authorizationContext.contextPath());
        }

        return processAuthorizationFlow(authorizationContext, signedJwt, registeredClient);
    }

    private Authentication handleOIDCStandardRequest(AuthorizationContext authorizationContext,
                                                     RegisteredClient registeredClient) {
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), null,
                authorizationContext.originalRequestURL(), authorizationContext.portalUrl(), authorizationContext.contextPath());

        cacheAuthorizationRequest(authorizationContext, registeredClient.getClientId(), authorizationContext.redirectUri());

        // Delegate JWT building, signing, caching, and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.buildAuthorizationRequest(
                registeredClient, authorizationContext.scope(), authorizationContext.state());

        return throwRedirectAuthentication(authorizationContext.state(), result, registeredClient,
                authorizationContext.portalUrl(), authorizationContext.contextPath());
    }

    private Authentication processAuthorizationFlow(AuthorizationContext authorizationContext,
                                                    SignedJWT signedJwt,
                                                    RegisteredClient registeredClient) {
        PublicKey publicKey = didService.resolvePublicKeyFromDid(registeredClient.getClientId());
        jwtService.verifyJWTWithECKey(signedJwt.serialize(), publicKey);

        cacheAuthorizationRequest(
                authorizationContext,
                registeredClient.getClientId(),
                jwtService.extractClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI));

        // Delegate JWT building, signing, caching, and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.buildAuthorizationRequest(
                registeredClient, authorizationContext.scope(), authorizationContext.state());

        return throwRedirectAuthentication(authorizationContext.state(), result, registeredClient,
                authorizationContext.portalUrl(), authorizationContext.contextPath());
    }

    /**
     * Throws the redirect exception that Spring Authorization Server uses to redirect the user
     * to the login/QR page with the openid4vp URL.
     * If the client has a custom loginPageUri, redirect there instead of the default MFE Login.
     */
    private Authentication throwRedirectAuthentication(String state, AuthorizationRequestBuildWorkflow.Result result,
                                                       RegisteredClient registeredClient, String portalUrl,
                                                       String contextPath) {
        Map<String, Object> clientSettings = registeredClient.getClientSettings().getSettings();
        String loginPageUri = clientSettings.containsKey(CLIENT_SETTING_LOGIN_PAGE_URI)
                ? (String) clientSettings.get(CLIENT_SETTING_LOGIN_PAGE_URI)
                : null;

        String redirectUrl;
        if (loginPageUri != null) {
            // Custom login pages manage their own post-authentication navigation; homeUri is only for the default MFE Login
            redirectUrl = String.format(
                    "%s?authRequest=%s&state=%s",
                    loginPageUri,
                    URLEncoder.encode(result.openid4vpUrl(), StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8)
            );
        } else {
            redirectUrl = String.format(
                    "%s%s/login?authRequest=%s&state=%s&homeUri=%s",
                    portalUrl,
                    nullSafeContextPath(contextPath),
                    URLEncoder.encode(result.openid4vpUrl(), StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8),
                    URLEncoder.encode(result.homeUri(), StandardCharsets.UTF_8)
            );
        }

        OAuth2Error error = new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "Redirection required", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    // --- Validation methods (framework-level, kept in filter) ---

    private void throwInvalidClientAuthenticationException(String errorMessage, String clientName,
                                                           String errorCode, String originalRequestURL,
                                                           String portalUrl, String contextPath) {
        String redirectUrl = String.format(
                "%s%s/error?errorCode=%s&errorMessage=%s&clientUrl=%s&originalRequestURL=%s",
                portalUrl,
                nullSafeContextPath(contextPath),
                URLEncoder.encode(errorCode, StandardCharsets.UTF_8),
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8),
                URLEncoder.encode(clientName, StandardCharsets.UTF_8),
                URLEncoder.encode(originalRequestURL, StandardCharsets.UTF_8)
        );
        OAuth2Error error = new OAuth2Error("invalid_client_authentication", errorMessage, redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * Returns the servlet context-path, defaulting to an empty string when absent (root deployment).
     * Ensures URLs are well-formed regardless of whether a context-path is configured.
     */
    private String nullSafeContextPath(String contextPath) {
        return contextPath == null ? "" : contextPath;
    }

    private String retrieveJwtFromRequestUriOrRequest(String requestUri, HttpServletRequest request,
                                                      RegisteredClient registeredClient, String originalRequestURL,
                                                      String portalUrl, String contextPath) {
        if (requestUri != null) {
            try {
                // SEC-14: SSRF protection — validate URL before outbound request
                safeUrlValidator.validate(requestUri);
                log.info("Retrieving JWT from request_uri: {}", requestUri);
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(requestUri)).timeout(REQUEST_TIMEOUT).GET().build();
                HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

                if (httpResponse.statusCode() != 200 || StringUtils.isBlank(httpResponse.body())) {
                    String errorCode = UUID.randomUUID().toString();
                    throwInvalidClientAuthenticationException("Failed to retrieve JWT from request_uri: Invalid response.",
                            registeredClient.getClientName(), errorCode, originalRequestURL, portalUrl, contextPath);
                }
                return httpResponse.body();
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                String errorCode = UUID.randomUUID().toString();
                throwInvalidClientAuthenticationException("Failed to retrieve JWT from request_uri.",
                        registeredClient.getClientName(), errorCode, originalRequestURL, portalUrl, contextPath);
            }
        }
        return request.getParameter("request");
    }

    private void validateOAuth2Parameters(RegisteredClient registeredClient, String scope,
                                          SignedJWT signedJwt, String originalRequestURL, String portalUrl,
                                          String contextPath) {
        Payload payload = signedJwt.getPayload();
        String jwtClientId = jwtService.extractClaimFromPayload(payload, CLIENT_ID);
        String jwtScope = jwtService.extractClaimFromPayload(payload, SCOPE);

        if (!registeredClient.getClientId().equals(jwtClientId) || !scope.equals(jwtScope)) {
            throwInvalidClientAuthenticationException("The OAuth 2.0 parameters do not match the JWT claims.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL, portalUrl, contextPath);
        }
    }

    private void validateRedirectUri(RegisteredClient registeredClient, String redirectUri,
                                     SignedJWT signedJwt, String originalRequestURL, String portalUrl,
                                     String contextPath) {
        String jwtRedirectUri = signedJwt != null
                ? jwtService.extractClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI)
                : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            throwInvalidClientAuthenticationException("The redirect_uri does not match any of the registered client's redirect_uris.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL, portalUrl, contextPath);
        }
    }

    private void validateNonceRequired(String clientNonce, RegisteredClient registeredClient,
                                       String originalRequestURL, String portalUrl, String contextPath) {
        if (StringUtils.isBlank(clientNonce)) {
            throwInvalidClientAuthenticationException("The 'nonce' parameter is required but is missing.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL, portalUrl, contextPath);
        }
    }

    private void cacheAuthorizationRequest(AuthorizationContext authorizationContext, String clientId, String redirectUri) {
        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .authorizationCode()
                .state(authorizationContext.state())
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(authorizationContext.scope())
                .authorizationUri(backendConfig.getUrl());

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(EXPIRATION, Instant.now().plusSeconds(loginTimeoutSeconds).getEpochSecond());

        String nonce = authorizationContext.clientNonce();
        if (nonce != null && !nonce.isBlank()) {
            additionalParameters.put(NONCE, nonce);
        }
        String codeChallenge = authorizationContext.codeChallenge();
        if (codeChallenge != null && !codeChallenge.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        String codeChallengeMethod = authorizationContext.codeChallengeMethod();
        if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }

        builder.additionalParameters(additionalParameters);
        cacheStoreForOAuth2AuthorizationRequest.add(authorizationContext.state(), builder.build());
    }

    /**
     * Derives the portal base URL from the incoming request, using X-Forwarded headers
     * set by nginx. In multi-tenant mode, each tenant has its own subdomain
     * (e.g., kpmg.127.0.0.1.nip.io), so the portal URL must match the request origin.
     */
    private String resolvePortalUrlFromRequest(HttpServletRequest request) {
        String host = request.getHeader("X-Forwarded-Host");
        if (host == null || host.isBlank()) {
            host = request.getServerName();
            int port = request.getServerPort();
            if (port != 80 && port != 443) {
                host = host + ":" + port;
            }
        }
        String scheme = request.getHeader("X-Forwarded-Proto");
        if (scheme == null || scheme.isBlank()) {
            scheme = request.getScheme();
        }
        return scheme + "://" + host;
    }

    private String getFullRequestUrl(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL());
        String queryString = request.getQueryString();
        if (queryString != null) {
            requestURL.append('?').append(queryString);
        }
        return requestURL.toString();
    }
}
