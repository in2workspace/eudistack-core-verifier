package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import static es.in2.vcverifier.shared.domain.util.Constants.INVALID_CLIENT_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUIRED_EXTERNAL_USER_AUTHENTICATION;

/**
 * A browser redirect decided by {@link CustomAuthorizationRequestConverter}: the only exception
 * {@link CustomErrorResponseHandler} turns into a redirect. Any other
 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} (e.g. Spring's own validation
 * errors, whose {@code uri} is just a documentation link) is answered with a 400.
 *
 * <p>The target is the error {@code uri}; the error code is internal (logs) except for
 * {@link #toClient} responses, where it is the OAuth2 error already encoded in the location.
 */
public final class AuthorizationRedirectException extends OAuth2AuthorizationCodeRequestAuthenticationException {

    private final boolean loginPage;

    private AuthorizationRedirectException(OAuth2Error error, boolean loginPage) {
        super(error, null);
        this.loginPage = loginPage;
    }

    /** The login (QR) page of the OID4VP flow. The only redirect that carries the EUD-252 browser binding. */
    public static AuthorizationRedirectException toLoginPage(String location) {
        return new AuthorizationRedirectException(
                new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "Redirection required", location), true);
    }

    /** The Verifier error page, for requests that cannot be answered to the client's redirect_uri. */
    public static AuthorizationRedirectException toErrorPage(String errorMessage, String location) {
        return new AuthorizationRedirectException(
                new OAuth2Error(INVALID_CLIENT_AUTHENTICATION, errorMessage, location), false);
    }

    /**
     * An authorization response (OIDC error) to the client's already-validated redirect_uri;
     * {@code location} already carries {@code error}, {@code error_description}, {@code state} and {@code iss}.
     */
    public static AuthorizationRedirectException toClient(String errorCode, String errorDescription, String location) {
        return new AuthorizationRedirectException(new OAuth2Error(errorCode, errorDescription, location), false);
    }

    /** SSO reuse: the code was already issued, {@code location} is the client's redirect_uri carrying it. */
    public static AuthorizationRedirectException toClientWithCode(String location) {
        return new AuthorizationRedirectException(
                new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "SSO session reused", location), false);
    }

    public String location() {
        return getError().getUri();
    }

    /** Whether this is the login-page redirect (EUD-252: the only one that binds the login to the browser). */
    public boolean isLoginPage() {
        return loginPage;
    }
}
