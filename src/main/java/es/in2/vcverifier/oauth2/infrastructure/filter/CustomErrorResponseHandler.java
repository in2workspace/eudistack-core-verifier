package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
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

import static es.in2.vcverifier.shared.domain.util.Constants.INVALID_CLIENT_AUTHENTICATION;
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
            // Redirect to the URI contained, if the error code is required_external_user_authentication or invalid_client_authentication
            if (error.getErrorCode().equals(REQUIRED_EXTERNAL_USER_AUTHENTICATION) || error.getErrorCode().equals(INVALID_CLIENT_AUTHENTICATION)) {
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
            URI parsed = URI.create(uri);
            String scheme = parsed.getScheme();
            String origin = scheme + "://" + parsed.getAuthority();

            if (!"https".equals(scheme)) {
                return false;
            }
            // Allow registered client origins (includes loginPageUri origins) — enforce HTTPS
            if (allowedClientsOrigins.contains(origin)) {
                return true;
            }
            // Allow the verifier's own origin (for /login and /error internal redirects).
            // SEC-S7: still safe — backendConfig.getUrl() is derived from the trusted
            // ForwardedHeaderFilter-resolved host, not from raw user input.
            URI verifierUri = URI.create(backendConfig.getUrl());
            String verifierOrigin = verifierUri.getScheme() + "://" + verifierUri.getAuthority();
            return verifierOrigin.equals(origin);
        } catch (Exception e) {
            return false;
        }
    }
}

