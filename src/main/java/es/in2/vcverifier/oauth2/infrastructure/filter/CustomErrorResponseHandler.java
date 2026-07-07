package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

import static es.in2.vcverifier.shared.domain.util.Constants.INTERACTION_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.INVALID_CLIENT_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_REQUIRED;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUIRED_EXTERNAL_USER_AUTHENTICATION;

@Slf4j
@RequiredArgsConstructor
public class CustomErrorResponseHandler implements AuthenticationFailureHandler {

    private final Set<String> allowedClientsOrigins;
    private final BackendConfig backendConfig;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException oAuth2Exception) {
            OAuth2Error error = oAuth2Exception.getError();
            // Redirect to the URI in the error for codes that carry a client-facing redirect destination.
            if (error.getErrorCode().equals(REQUIRED_EXTERNAL_USER_AUTHENTICATION)
                    || error.getErrorCode().equals(INVALID_CLIENT_AUTHENTICATION)
                    || error.getErrorCode().equals(LOGIN_REQUIRED)
                    || error.getErrorCode().equals(INTERACTION_REQUIRED)) {
                String redirectUri = error.getUri();
                // SEC-S7: Validate redirect URI belongs to a registered client origin to prevent open redirect.
                if (redirectUri != null && isAllowedRedirectUri(redirectUri)) {
                    response.sendRedirect(redirectUri);
                    return;
                }
                log.warn("Blocked redirect to untrusted URI: {}", redirectUri);
            }
        }

        // Handle other unexpected errors
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    private boolean isAllowedRedirectUri(String uri) {
        try {
            String scheme = URI.create(uri).getScheme();
            if (!"https".equalsIgnoreCase(scheme)) {
                return false;
            }

            String origin = OriginNormalizer.normalizeOrigin(uri);
            if (origin == null) {
                return false;
            }

            log.debug("Validating redirect URI. allowedClientsOrigins={}, origin={}", allowedClientsOrigins, origin);

            // Allow registered client origins (includes loginPageUri origins) — enforce HTTPS
            if (allowedClientsOrigins.contains(origin)) {
                return true;
            }
            // Allow the verifier's own origin(s), for /login and /error internal redirects.
            // SEC-S7: deliberately static and configuration-driven (BackendConfig#getTrustedVerifierOrigins)
            // — never derived from the request Host, so a single misconfigured or compromised
            // proxy hop cannot widen the set of trusted redirect targets. Supports multiple
            // alias domains for multi-tenant/multi-app SSO deployments.
            return backendConfig.getTrustedVerifierOrigins().contains(origin);
        } catch (Exception e) {
            return false;
        }
    }
}

