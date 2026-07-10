package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.UUID;

import static es.in2.vcverifier.oauth2.infrastructure.filter.UnregisteredM2MClientAuthenticationConverter.UNREGISTERED_VC_METHOD;

/**
 * Marks an {@link UnregisteredM2MClientAuthenticationConverter} authentication request as
 * authenticated so it can pass Spring's {@code anyRequest().authenticated()} gate on the
 * authorization server endpoints.
 *
 * The {@link RegisteredClient} built here is a placeholder only — it carries no trust and
 * is discarded after this step. It exists solely because
 * {@link OAuth2ClientAuthenticationToken}'s authenticated constructor requires one.
 * {@link CustomAuthenticationProvider#getOrBuildRegisteredClient} performs its own
 * independent {@code registeredClientRepository.findByClientId} lookup afterwards and
 * derives the real client identity and tenant from the validated credential.
 */
public class UnregisteredM2MClientAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
        if (!UNREGISTERED_VC_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient placeholderClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientAuthenticationMethod(UNREGISTERED_VC_METHOD)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        return new OAuth2ClientAuthenticationToken(placeholderClient, UNREGISTERED_VC_METHOD,
                clientAuthentication.getCredentials());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
