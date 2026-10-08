package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

/**
 * Aborts a pending cross-device (QR) login and returns the user to the Relying Party that
 * started it, with an OAuth2 error response (RFC 6749 §4.1.2.1). Only the Verifier knows that
 * Relying Party: its validated {@code redirect_uri} is cached under the login {@code state}.
 *
 * <p>Removing the cached request also prevents a late wallet presentation from completing a
 * login the user already saw as expired. The removal is atomic and the presentation flow takes
 * the request the same way, so abort and completion are mutually exclusive: when the
 * presentation wins, abort returns empty and the redirect reaches the browser over SSE.
 *
 * <p>Only an expired login can be aborted: a login still in progress is left untouched.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AbortLoginWorkflow {

    private static final String LOGIN_TIMEOUT_DESCRIPTION = "login_timeout";

    /**
     * The browser's countdown starts after {@code /authorize} set the expiration, so it never
     * ends earlier; this only absorbs clock and timer imprecision.
     */
    private static final long EXPIRATION_MARGIN_SECONDS = 5;

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    /**
     * @return the Relying Party redirect URL, or empty when no login is pending for {@code state}
     *         or it has not expired yet
     */
    public Optional<String> abort(String state) {
        // The endpoint is public and the state is not a secret (the wallet sees it): only an
        // expired login may be aborted, or anyone could cut a login in progress.
        OAuth2AuthorizationRequest pending = cacheStoreForOAuth2AuthorizationRequest.getIfPresent(state);
        if (pending != null && !hasExpired(pending)) {
            log.warn("Rejected abort of a login that has not expired yet, state={}", sanitize(state));
            return Optional.empty();
        }

        OAuth2AuthorizationRequest authorizationRequest = cacheStoreForOAuth2AuthorizationRequest.remove(state);
        if (authorizationRequest == null) {
            log.debug("No pending login to abort for state={}", sanitize(state));
            return Optional.empty();
        }

        log.info("Login aborted for client={}", sanitize(authorizationRequest.getClientId()));
        return Optional.of(buildErrorRedirect(authorizationRequest.getRedirectUri(), state));
    }

    private boolean hasExpired(OAuth2AuthorizationRequest authorizationRequest) {
        if (!(authorizationRequest.getAdditionalParameters().get(EXPIRATION) instanceof Number expiration)) {
            return false;
        }
        return Instant.now().getEpochSecond() >= expiration.longValue() - EXPIRATION_MARGIN_SECONDS;
    }

    private String buildErrorRedirect(String redirectUri, String state) {
        String separator = redirectUri.contains("?") ? "&" : "?";
        return redirectUri + separator
                + "error=" + OAuth2ErrorCodes.ACCESS_DENIED
                + "&error_description=" + LOGIN_TIMEOUT_DESCRIPTION
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }
}
