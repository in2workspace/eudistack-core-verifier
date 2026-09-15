package es.in2.vcverifier.oauth2.infrastructure.filter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Lets a refresh_token request through Spring's client authentication step for a
 * PUBLIC client (clientAuthenticationMethod NONE — no secret, PKCE-based login).
 *
 * Spring's built-in {@code PublicClientAuthenticationConverter}/{@code Provider} only
 * authenticate a "none"-method client for the authorization_code grant (PKCE
 * code_verifier validation only makes sense there) — there is no built-in path for a
 * public client to authenticate a refresh_token request, so such a client was rejected
 * with a bare 401 before ever reaching {@link CustomTokenRequestConverter} /
 * {@link CustomAuthenticationProvider}, which already fully implement the refresh flow
 * (one-time-use rotation, cached-credential recovery).
 *
 * This converter performs NO validation of its own beyond confirming the client is a
 * pre-registered public client — possession of a still-valid (not yet rotated out)
 * refresh token is what actually authorizes the request, checked downstream by
 * {@link CustomAuthenticationProvider} against the refresh-token cache.
 */
@RequiredArgsConstructor
public class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    public static final ClientAuthenticationMethod PUBLIC_CLIENT_REFRESH_TOKEN_METHOD =
            new ClientAuthenticationMethod("urn:eudistack:oauth:client-authentication-type:public-client-refresh-token");

    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return null;
        }

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        // Confidential clients (secret, assertion, mTLS) keep using Spring's built-in
        // mechanisms untouched — this converter only steps in for genuinely public clients.
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null
                || !registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            return null;
        }

        return new OAuth2ClientAuthenticationToken(clientId, PUBLIC_CLIENT_REFRESH_TOKEN_METHOD, null, null);
    }
}
