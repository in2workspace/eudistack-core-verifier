package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

@Slf4j
@RequiredArgsConstructor
public class CustomErrorResponseHandler implements AuthenticationFailureHandler {

    private final Set<String> allowedClientsOrigins;
    private final BackendConfig backendConfig;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        // Only redirects our converter decided on are followed. Any other exception — including
        // Spring's own OAuth2AuthorizationCodeRequestAuthenticationException, whose uri is just a
        // documentation link — is answered with a 400, whatever its error code or uri.
        if (exception instanceof AuthorizationRedirectException redirect) {
            String location = redirect.location();
            // SEC-S7: second layer — the target must still belong to a registered client origin (or
            // the Verifier itself) over HTTPS, to prevent an open redirect.
            if (location != null && isAllowedRedirectUri(location)) {
                if (redirect.isLoginPage()) {
                    // EUD-252: login-page redirect of an SSO tenant — bind the login to this
                    // browser. Always re-emitted (also when reused) to refresh its Max-Age.
                    SsoBrowserBindingCookie.pendingCookie(request)
                            .ifPresent(cookie -> response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString()));
                }
                response.sendRedirect(location);
                return;
            }
            log.warn("event=authorize_redirect_blocked error={} origin={}", redirect.getError().getErrorCode(),
                    sanitize(originOf(location)));
        }

        // Handle other unexpected errors
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    /** Origin only: the location may carry an authorization code or the client's state. */
    private static String originOf(String uri) {
        URI origin = OriginNormalizer.normalize(uri);
        return origin != null ? origin.toString() : null;
    }

    private boolean isAllowedRedirectUri(String uri) {
        try {
            URI parsed = URI.create(uri);
            if (!"https".equalsIgnoreCase(parsed.getScheme())) {
                return false;
            }

            URI origin = OriginNormalizer.normalize(parsed);
            if (origin == null) {
                return false;
            }
            String originString = origin.toString();

            log.debug("Validating redirect URI. allowedClientsOrigins={}, origin={}", allowedClientsOrigins, originString);

            // Allow registered client origins (includes loginPageUri origins) — enforce HTTPS
            if (allowedClientsOrigins.contains(originString)) {
                return true;
            }
            return backendConfig.getTrustedVerifierOrigins().contains(originString);
        } catch (Exception e) {
            return false;
        }
    }
}

