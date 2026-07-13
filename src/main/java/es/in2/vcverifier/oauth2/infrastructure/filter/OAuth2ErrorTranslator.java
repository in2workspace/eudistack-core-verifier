package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Builds {@link OAuth2AuthenticationException} instances for the standard error codes used
 * across the token endpoint filter chain (CustomAuthenticationProvider, CustomTokenRequestConverter).
 * Every instance carries only the error code — no description/uri — so no internal exception
 * detail ever reaches the OAuth2 error response returned to the client. Callers throw the
 * returned exception explicitly at the point of failure.
 */
public final class OAuth2ErrorTranslator {

    private OAuth2ErrorTranslator() {} // utility class

    public static OAuth2AuthenticationException invalidClient() {
        return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    public static OAuth2AuthenticationException invalidGrant() {
        return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
    }

    public static OAuth2AuthenticationException serverError() {
        return new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
    }
}
