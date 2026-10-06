package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

/**
 * Aborts a pending cross-device (QR) login and returns the user to the Relying Party that
 * started it, with an OAuth2 error response (RFC 6749 §4.1.2.1). Only the Verifier knows that
 * Relying Party: its validated {@code redirect_uri} is cached under the login {@code state}.
 *
 * <p>Removing the cached request also prevents a late wallet presentation from completing a
 * login the user already saw as expired.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AbortLoginWorkflow {

    private static final String LOGIN_TIMEOUT_DESCRIPTION = "login_timeout";

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    /**
     * @return the Relying Party redirect URL, or empty when no login is pending for {@code state}
     */
    public Optional<String> abort(String state) {
        OAuth2AuthorizationRequest authorizationRequest = cacheStoreForOAuth2AuthorizationRequest.getIfPresent(state);
        if (authorizationRequest == null) {
            log.debug("No pending login to abort for state={}", sanitize(state));
            return Optional.empty();
        }
        cacheStoreForOAuth2AuthorizationRequest.delete(state);

        log.info("Login aborted for client={}", sanitize(authorizationRequest.getClientId()));
        return Optional.of(buildErrorRedirect(authorizationRequest.getRedirectUri(), state));
    }

    private String buildErrorRedirect(String redirectUri, String state) {
        String separator = redirectUri.contains("?") ? "&" : "?";
        return redirectUri + separator
                + "error=" + OAuth2ErrorCodes.ACCESS_DENIED
                + "&error_description=" + LOGIN_TIMEOUT_DESCRIPTION
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }
}
