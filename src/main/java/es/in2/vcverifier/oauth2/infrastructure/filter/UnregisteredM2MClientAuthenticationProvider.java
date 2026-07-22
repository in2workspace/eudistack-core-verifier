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
 *
 * SEC: the placeholder's grant type is deliberately a bogus, non-standard value
 * ({@link #PLACEHOLDER_GRANT_TYPE}) rather than {@code CLIENT_CREDENTIALS}.
 * {@code OAuth2ClientAuthenticationConfigurer#authenticationProvider} / the equivalent
 * token-endpoint configurer APPEND to Spring's own provider lists rather than replacing
 * them, so Spring's built-in {@code OAuth2ClientCredentialsAuthenticationProvider} remains
 * in the chain. If the placeholder declared CLIENT_CREDENTIALS, that built-in provider
 * would independently accept it too and mint a token with none of our credential/tenant
 * validation — bypassing CustomAuthenticationProvider entirely. A grant type no built-in
 * provider recognizes ensures every one of them rejects the placeholder, so only our own
 * downstream validation can ever produce a token for an unregistered client.
 */
public class UnregisteredM2MClientAuthenticationProvider implements AuthenticationProvider {

    private static final AuthorizationGrantType PLACEHOLDER_GRANT_TYPE =
            new AuthorizationGrantType("urn:eudistack:oauth:grant-type:unregistered-vc-placeholder");

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
                .authorizationGrantType(PLACEHOLDER_GRANT_TYPE)
                .build();

        return new OAuth2ClientAuthenticationToken(placeholderClient, UNREGISTERED_VC_METHOD,
                clientAuthentication.getCredentials());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
