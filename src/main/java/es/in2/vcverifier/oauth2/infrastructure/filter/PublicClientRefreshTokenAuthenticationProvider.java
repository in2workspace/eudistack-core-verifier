package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static es.in2.vcverifier.oauth2.infrastructure.filter.PublicClientRefreshTokenAuthenticationConverter.PUBLIC_CLIENT_REFRESH_TOKEN_METHOD;

/**
 * Marks a {@link PublicClientRefreshTokenAuthenticationConverter} authentication request as
 * authenticated so it can pass Spring's {@code anyRequest().authenticated()} gate on the
 * authorization server endpoints.
 *
 * Unlike {@link UnregisteredM2MClientAuthenticationProvider} (which builds a placeholder
 * client because the real one doesn't exist yet), this client IS already registered —
 * the converter already validated it exists and is public, so this simply re-fetches it
 * to build the authenticated token. The actual authorization check (does a cached,
 * not-yet-rotated refresh token for this client exist?) happens downstream in
 * {@link CustomAuthenticationProvider}.
 */
public class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;

    public PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
        if (!PUBLIC_CLIENT_REFRESH_TOKEN_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            return null;
        }

        return new OAuth2ClientAuthenticationToken(registeredClient, PUBLIC_CLIENT_REFRESH_TOKEN_METHOD, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
