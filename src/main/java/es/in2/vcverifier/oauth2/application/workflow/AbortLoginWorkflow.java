package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.util.AuthorizationResponseUri;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.Constants.BROWSER_BINDING_HASH;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

/**
 * Aborts a pending cross-device (QR) login and returns the user to the Relying Party that
 * started it, with an OAuth2 error response (RFC 6749 §4.1.2.1). Only the Verifier knows that
 * Relying Party: its validated {@code redirect_uri} is cached under the login {@code state}.
 *
 * <p>Removing the cached request also prevents a late wallet presentation from completing a
 * login the user already saw as expired. The removal is atomic and conditional on the entry
 * being the one checked, and the presentation flow takes the request atomically too, so abort
 * and completion are mutually exclusive: when the presentation wins, abort returns empty and
 * the redirect reaches the browser over SSE.
 *
 * <p>An expired login can be aborted from anywhere. A login still in progress can only be aborted
 * from the browser that started it, proved by its browser-binding cookie.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AbortLoginWorkflow {

    private static final String LOGIN_TIMEOUT_DESCRIPTION = "login_timeout";
    private static final String LOGIN_CANCELLED_DESCRIPTION = "login_cancelled";

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
        return abort(state, null);
    }

    /**
     * @param browserBindingHash SHA-256 (hex) of the browser-binding cookie of the request, or {@code null}
     */
    public Optional<String> abort(String state, String browserBindingHash) {
        // The endpoint is public and the state is not a secret (the wallet sees it): a login in
        // progress may only be aborted by the browser that started it, or anyone could cut it.
        OAuth2AuthorizationRequest pending = cacheStoreForOAuth2AuthorizationRequest.getIfPresent(state);
        if (pending == null) {
            log.debug("No pending login to abort for state={}", sanitize(state));
            return Optional.empty();
        }
        boolean expired = hasExpired(pending);
        if (!expired && !startedBy(pending, browserBindingHash)) {
            log.warn("Rejected abort of a login in progress from another browser, state={}", sanitize(state));
            return Optional.empty();
        }
        // Remove only the entry just checked: a wallet presentation may have taken it, or a
        // same-browser /authorize retry may have replaced it with a fresh login, in between.
        if (!cacheStoreForOAuth2AuthorizationRequest.remove(state, pending)) {
            log.debug("Pending login changed before it could be aborted, state={}", sanitize(state));
            return Optional.empty();
        }

        log.info("Login aborted for client={}", sanitize(pending.getClientId()));
        // iss (RFC 9207): the issuer of the /authorize request, cached with it.
        return Optional.of(AuthorizationResponseUri.error(pending.getRedirectUri(), OAuth2ErrorCodes.ACCESS_DENIED,
                expired ? LOGIN_TIMEOUT_DESCRIPTION : LOGIN_CANCELLED_DESCRIPTION, state, pending.getAuthorizationUri()));
    }

    private static boolean startedBy(OAuth2AuthorizationRequest authorizationRequest, String browserBindingHash) {
        if (browserBindingHash == null
                || !(authorizationRequest.getAdditionalParameters().get(BROWSER_BINDING_HASH) instanceof String expected)) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                browserBindingHash.getBytes(StandardCharsets.UTF_8));
    }

    private boolean hasExpired(OAuth2AuthorizationRequest authorizationRequest) {
        if (!(authorizationRequest.getAdditionalParameters().get(EXPIRATION) instanceof Number expiration)) {
            return false;
        }
        return Instant.now().getEpochSecond() >= expiration.longValue() - EXPIRATION_MARGIN_SECONDS;
    }
}
