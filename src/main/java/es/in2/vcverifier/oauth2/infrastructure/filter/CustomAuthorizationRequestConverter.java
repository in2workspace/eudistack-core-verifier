package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.oauth2.domain.model.OidcPrompt;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
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

import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.BROWSER_BINDING_HASH;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_ERROR_REDIRECT;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_ID;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.INTERACTION_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUEST_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUIRED_EXTERNAL_USER_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.util.Constants.SCOPE;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final String SSO_COOKIE_PREFIX = "__Secure-sso-";
    private static final String MAX_AGE_PARAMETER = "max_age";
    private static final String PROMPT_PARAMETER = "prompt";
    private static final String ACCESS_PROFILE_PARAMETER = "access_profile";

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
    private final SsoBrowserBindingCookie ssoBrowserBindingCookie;

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
                .maxAge(parseMaxAge(request.getParameter(MAX_AGE_PARAMETER)))
                .accessProfile(request.getParameter(ACCESS_PROFILE_PARAMETER))
                .build();

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Unauthorized client: Client with ID {} not found.", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Case 1: Standard OIDC authorization request without a signed JWT object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            return handleOIDCStandardRequest(authorizationContext, request, registeredClient);
        }

        // Case 2: FAPI authorization request with a signed JWT object
        return handleFAPIRequest(authorizationContext, request, registeredClient);
    }

    /** Tenant resolved at /authorize + browser binding (null when the tenant has no SSO). */
    private record LoginBinding(String tenant, String browserBindingHash) {
    }

    private LoginBinding bindLogin(HttpServletRequest request) {
        return new LoginBinding(TenantDomainFilter.getCurrentTenant(request),
                ssoBrowserBindingCookie.bindIfSsoEnabled(request));
    }

    /**
     * OIDC Core 1.0 §3.1.2.1 + EUD-300 FR-03/FR-05: decides whether the tenant SSO session is reused.
     * Must only be called once the request is fully validated (client, redirect_uri, and for JAR the
     * request object signature and claims): every redirect thrown here goes to {@code ctx.redirectUri()}.
     *
     * <ul>
     *   <li>{@code none} combined with another value → {@code invalid_request}.</li>
     *   <li>{@code login} → no reuse, the caller continues to the QR flow.</li>
     *   <li>{@code none} → ALLOWED redirects with the code; otherwise {@code login_required} /
     *       {@code interaction_required}, never UI.</li>
     *   <li>absent (or only unsupported values) → ALLOWED redirects with the code; any other outcome
     *       returns and the caller continues to the QR flow.</li>
     * </ul>
     *
     * <p>Returns normally only when the caller must continue to the OID4VP/QR flow.
     */
    private void attemptSsoReuse(HttpServletRequest request, AuthorizationContext ctx,
                                 RegisteredClient registeredClient, OidcPrompt prompt) {
        String clientId = registeredClient.getClientId();
        if (prompt.isInvalidNoneCombination()) {
            log.warn("event=authorize_prompt_invalid clientId={} reason=none_combined_with_other_values", clientId);
            throwOidcErrorRedirect(OAuth2ErrorCodes.INVALID_REQUEST, ctx);
        }
        if (prompt.requiresLogin()) {
            log.debug("event=sso_reuse_skipped clientId={} reason=prompt_login", clientId);
            return;
        }
        String tenant = TenantDomainFilter.getCurrentTenant(request);
        if (tenant == null || tenant.isBlank()) {
            if (prompt.isNone()) {
                throwOidcErrorRedirect(LOGIN_REQUIRED, ctx);
            }
            return;
        }
        // The reuse path issues a code without building an OID4VP request, so the scope check that
        // buildAuthorizationRequest does for the QR path has to run here first.
        authorizationRequestBuildWorkflow.validateScope(ctx.scope());

        ReuseSsoSessionWorkflow.Result result = prompt.isNone()
                ? reuseSsoSession(request, ctx, tenant, clientId)
                : reuseSsoSessionOrNull(request, ctx, tenant, clientId);
        ReuseSsoSessionWorkflow.Result.Status status = result != null ? result.status() : null;
        if (status == ReuseSsoSessionWorkflow.Result.Status.ALLOWED) {
            throwSsoReuseRedirect(result.redirectUrl());
        }
        if (prompt.isNone()) {
            throwOidcErrorRedirect(status == ReuseSsoSessionWorkflow.Result.Status.INTERACTION_REQUIRED
                    ? INTERACTION_REQUIRED : LOGIN_REQUIRED, ctx);
        }
        log.debug("event=sso_reuse_skipped tenant={} clientId={} reason={}", tenant, clientId,
                status != null ? status : "reuse_failed");
    }

    private ReuseSsoSessionWorkflow.Result reuseSsoSession(HttpServletRequest request, AuthorizationContext ctx,
                                                           String tenant, String clientId) {
        String cookieValue = extractCookieValue(request, SSO_COOKIE_PREFIX + tenant);
        // EUDISTACK-548: mirrors the sso_cookie_issued log — lets us see, side by side, whether the
        // exact cookie this request expected was ever actually presented by the browser. Cookie
        // value itself is never logged, only whether one was found.
        log.debug("event=sso_cookie_lookup tenant={} expectedCookieName={} found={}",
                tenant, SSO_COOKIE_PREFIX + tenant, cookieValue != null);
        String correlationId = UUID.randomUUID().toString();
        return reuseSsoSessionWorkflow.reuse(tenant, cookieValue, ctx, clientId, correlationId);
    }

    /**
     * Without {@code prompt}, reuse is only an optimisation over the normal login: an unexpected
     * failure while trying it must not break a login that would otherwise succeed, so it falls back
     * to the QR flow (fail-safe: no code is issued).
     */
    private ReuseSsoSessionWorkflow.Result reuseSsoSessionOrNull(HttpServletRequest request, AuthorizationContext ctx,
                                                                 String tenant, String clientId) {
        try {
            return reuseSsoSession(request, ctx, tenant, clientId);
        } catch (RuntimeException e) {
            // Throwable logged so a persistent reuse failure (cipher key, DB, bug) is debuggable;
            // reuse exception messages carry no session or credential data.
            log.warn("event=sso_reuse_failed tenant={} clientId={} error={}", tenant, clientId,
                    e.getClass().getSimpleName(), e);
            return null;
        }
    }

    /**
     * ALLOWED reuse: the code was already issued by ReuseSsoSessionWorkflow — redirect straight to
     * the RP with it, same mechanism throwRedirectAuthentication uses for the QR-page redirect
     * (an "error" whose uri is really just the next hop, not a real OAuth failure).
     */
    private void throwSsoReuseRedirect(String redirectUrl) {
        OAuth2Error error = new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "SSO session reused", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /** OIDC error response to the client; {@code ctx.redirectUri()} must already be validated against the client. */
    private void throwOidcErrorRedirect(String errorCode, AuthorizationContext ctx) {
        String location = ctx.redirectUri() + "?error=" + errorCode
                + (ctx.state() != null && !ctx.state().isBlank()
                   ? "&state=" + URLEncoder.encode(ctx.state(), StandardCharsets.UTF_8)
                   : "");
        OAuth2Error error = new OAuth2Error(errorCode, CLIENT_ERROR_REDIRECT, location);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * FR-21/AC-09: parsea el {@code max_age} OIDC (segundos, entero no negativo). Un valor
     * ausente o inválido se ignora (log warn) en vez de romper la petición — max_age es un
     * refinamiento de frescura sobre el flujo estándar, no una condición de seguridad dura.
     */
    private Long parseMaxAge(String rawMaxAge) {
        if (rawMaxAge == null || rawMaxAge.isBlank()) {
            return null;
        }
        try {
            long maxAge = Long.parseLong(rawMaxAge.trim());
            if (maxAge < 0) {
                log.warn("event=sso_max_age_invalid reason=negative value={}", sanitize(rawMaxAge));
                return null;
            }
            // W3 (review): an unbounded max_age (e.g. Long.MAX_VALUE) overflows
            // Instant.plusSeconds(...) in TenantSsoPolicy — ArithmeticException there would
            // surface as a 500 instead of login_required. Cap at the system's own max session
            // TTL: no session can ever be older than that anyway, so anything beyond it can
            // never actually force freshness and is treated the same as an absent max_age.
            if (maxAge > SsoTtlRange.MAX_ABSOLUTE.toSeconds()) {
                log.warn("event=sso_max_age_invalid reason=exceeds_max_ttl value={}", sanitize(rawMaxAge));
                return null;
            }
            return maxAge;
        } catch (NumberFormatException e) {
            log.warn("event=sso_max_age_invalid reason=not_a_number value={}", sanitize(rawMaxAge));
            return null;
        }
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

        return processAuthorizationFlow(authorizationContext, request, signedJwt, registeredClient);
    }

    private Authentication handleOIDCStandardRequest(AuthorizationContext authorizationContext,
                                                     HttpServletRequest request,
                                                     RegisteredClient registeredClient) {
        // redirect_uri is validated BEFORE any SSO-reuse decision: both the reuse code redirect and
        // the prompt=none / invalid_request error redirects target it.
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), null,
                authorizationContext.originalRequestURL(), authorizationContext.portalUrl(), authorizationContext.contextPath());

        attemptSsoReuse(request, authorizationContext, registeredClient,
                OidcPrompt.parse(request.getParameter(PROMPT_PARAMETER)));

        // Delegate JWT building, signing and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.buildAuthorizationRequest(
                registeredClient, authorizationContext.scope(), authorizationContext.state(),
                authorizationContext.accessProfile());

        // EUD-252: bound only AFTER the reuse branch — an SSO-reuse redirect to the RP must not
        // carry the login-page browser-binding cookie.
        cacheAuthorizationRequest(authorizationContext, registeredClient, authorizationContext.redirectUri(),
                bindLogin(request), result.vpNonce());

        return throwRedirectAuthentication(authorizationContext.state(), result, registeredClient,
                authorizationContext.portalUrl(), authorizationContext.contextPath());
    }

    private Authentication processAuthorizationFlow(AuthorizationContext authorizationContext,
                                                    HttpServletRequest request,
                                                    SignedJWT signedJwt,
                                                    RegisteredClient registeredClient) {
        PublicKey publicKey = didService.resolvePublicKeyFromDid(registeredClient.getClientId());
        jwtService.verifyJWTWithECKey(signedJwt.serialize(), publicKey);

        String jwtRedirectUri = jwtService.extractClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI);

        // RFC 9101 §6.3: the request object is authoritative — prompt and max_age come from its
        // (now signature-verified) claims, never from the query string. The reuse context also
        // targets the validated request-object redirect_uri, the same one cached for the QR path.
        Map<String, Object> claims = signedJwt.getPayload().toJSONObject();
        AuthorizationContext reuseContext = authorizationContext.toBuilder()
                .redirectUri(jwtRedirectUri)
                .maxAge(parseMaxAge(optionalClaim(claims, MAX_AGE_PARAMETER)))
                .build();
        attemptSsoReuse(request, reuseContext, registeredClient,
                OidcPrompt.parse(optionalClaim(claims, PROMPT_PARAMETER)));

        // Delegate JWT building, signing and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.buildAuthorizationRequest(
                registeredClient, authorizationContext.scope(), authorizationContext.state(),
                authorizationContext.accessProfile());

        // EUD-252: bound only AFTER the reuse branch, same as the plain path.
        cacheAuthorizationRequest(authorizationContext, registeredClient, jwtRedirectUri,
                bindLogin(request), result.vpNonce());

        return throwRedirectAuthentication(authorizationContext.state(), result, registeredClient,
                authorizationContext.portalUrl(), authorizationContext.contextPath());
    }

    /** Optional string/number claim of the request object; {@code null} when absent or of another type. */
    private static String optionalClaim(Map<String, Object> claims, String name) {
        Object value = claims == null ? null : claims.get(name);
        if (value instanceof String s) {
            return s;
        }
        if (value instanceof Number n) {
            return n.toString();
        }
        return null;
    }

    private Authentication throwRedirectAuthentication(String state, AuthorizationRequestBuildWorkflow.Result result,
                                                       RegisteredClient registeredClient, String portalUrl,
                                                       String contextPath) {
        Map<String, Object> clientSettings = registeredClient.getClientSettings().getSettings();
        String loginPageUri = clientSettings.containsKey(CLIENT_SETTING_LOGIN_PAGE_URI)
                ? (String) clientSettings.get(CLIENT_SETTING_LOGIN_PAGE_URI)
                : null;

        String redirectUrl;
        if (loginPageUri != null) {
            redirectUrl = String.format(
                    "%s?authRequest=%s&state=%s",
                    loginPageUri,
                    URLEncoder.encode(result.openid4vpUrl(), StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8)
            );
        } else {
            redirectUrl = String.format(
                    "%s%s/login?authRequest=%s&state=%s",
                    portalUrl,
                    nullSafeContextPath(contextPath),
                    URLEncoder.encode(result.openid4vpUrl(), StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8)
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

        String normalizedJwtRedirectUri = OriginNormalizer.normalizeUri(jwtRedirectUri);
        boolean isRedirectUriRegistered = normalizedJwtRedirectUri != null && registeredClient.getRedirectUris().stream()
                .anyMatch(registered -> normalizedJwtRedirectUri.equals(OriginNormalizer.normalizeUri(registered)));

        if (!isRedirectUriRegistered) {
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

    /**
     * Caches the in-flight login under its {@code state}, together with everything the wallet POST
     * will check: PKCE, client nonce, the OID4VP nonce, the /authorize tenant and the browser binding.
     *
     * <p>EUD-252 (F1): the RP-chosen {@code state} is public, so the write is put-if-absent: a second
     * /authorize with a state already in flight must not replace the victim's binding, PKCE or nonce
     * (session takeover, or at least DoS). The only accepted replacement is the same browser retrying
     * the same client/redirect_uri (equal non-null binding hashes), done with an atomic compare-and-
     * replace. Request and OID4VP nonce live in this one entry, so they always come from the same call.
     */
    private void cacheAuthorizationRequest(AuthorizationContext authorizationContext, RegisteredClient registeredClient,
                                           String redirectUri, LoginBinding loginBinding, String vpNonce) {
        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .authorizationCode()
                .state(authorizationContext.state())
                .clientId(registeredClient.getClientId())
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
        if (loginBinding.browserBindingHash() != null) {
            additionalParameters.put(BROWSER_BINDING_HASH, loginBinding.browserBindingHash());
        }
        if (vpNonce != null) {
            additionalParameters.put(VP_NONCE, vpNonce);
        }
        if (loginBinding.tenant() != null) {
            additionalParameters.put(AUTHORIZE_TENANT, loginBinding.tenant());
        }

        builder.additionalParameters(additionalParameters);
        String state = authorizationContext.state();
        if (state == null || state.isBlank()) {
            return; // nothing to key the login by: same as before (CacheStore.add ignored blank keys)
        }
        OAuth2AuthorizationRequest candidate = builder.build();
        OAuth2AuthorizationRequest existing = cacheStoreForOAuth2AuthorizationRequest.putIfAbsent(state, candidate);
        if (existing == null) {
            return;
        }
        if (isSameBrowserRetry(existing, candidate)
                && cacheStoreForOAuth2AuthorizationRequest.replace(state, existing, candidate)) {
            log.info("event=authorize_state_retry_same_browser clientId={}", registeredClient.getClientId());
            return;
        }
        log.warn("event=authorize_state_in_use clientId={} bound={}", registeredClient.getClientId(),
                loginBinding.browserBindingHash() != null);
        throwInvalidClientAuthenticationException("invalid_request: state already in use",
                registeredClient.getClientName(), UUID.randomUUID().toString(),
                authorizationContext.originalRequestURL(), authorizationContext.portalUrl(),
                authorizationContext.contextPath());
    }

    private static boolean isSameBrowserRetry(OAuth2AuthorizationRequest existing, OAuth2AuthorizationRequest candidate) {
        Object existingBinding = existing.getAdditionalParameters().get(BROWSER_BINDING_HASH);
        Object candidateBinding = candidate.getAdditionalParameters().get(BROWSER_BINDING_HASH);
        return existingBinding != null
                && existingBinding.equals(candidateBinding)
                && Objects.equals(existing.getClientId(), candidate.getClientId())
                && Objects.equals(existing.getRedirectUri(), candidate.getRedirectUri());
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
