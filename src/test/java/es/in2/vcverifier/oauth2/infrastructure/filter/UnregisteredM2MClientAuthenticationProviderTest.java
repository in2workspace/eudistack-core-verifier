package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class UnregisteredM2MClientAuthenticationProviderTest {

    private final UnregisteredM2MClientAuthenticationProvider provider = new UnregisteredM2MClientAuthenticationProvider();

    @Test
    @DisplayName("authenticate_unregisteredVcMethod_returnsAuthenticatedTokenWithPlaceholderClient")
    void authenticate_unregisteredVcMethod_returnsAuthenticatedTokenWithPlaceholderClient() {
        OAuth2ClientAuthenticationToken request = new OAuth2ClientAuthenticationToken(
                "unregistered-machine-client",
                UnregisteredM2MClientAuthenticationConverter.UNREGISTERED_VC_METHOD,
                "assertion-jwt",
                Collections.emptyMap());

        Authentication result = provider.authenticate(request);

        assertNotNull(result);
        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) result;
        assertTrue(token.isAuthenticated());
        assertEquals("unregistered-machine-client", token.getPrincipal());
        assertEquals("assertion-jwt", token.getCredentials());
        assertNotNull(token.getRegisteredClient());
        assertEquals("unregistered-machine-client", token.getRegisteredClient().getClientId());
        // SEC: the placeholder must NOT declare CLIENT_CREDENTIALS (or any grant type Spring's
        // built-in OAuth2ClientCredentialsAuthenticationProvider recognizes) — otherwise that
        // built-in provider, which remains in the chain alongside ours, could independently
        // mint a token for this placeholder without ever running our credential/tenant checks.
        assertFalse(token.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS));
        assertFalse(token.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        assertFalse(token.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
    }

    @Test
    @DisplayName("authenticate_differentClientAuthenticationMethod_returnsNull")
    void authenticate_differentClientAuthenticationMethod_returnsNull() {
        OAuth2ClientAuthenticationToken request = new OAuth2ClientAuthenticationToken(
                "some-client",
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                "secret",
                Collections.emptyMap());

        Authentication result = provider.authenticate(request);

        assertNull(result);
    }

    @Test
    @DisplayName("supports_oauth2ClientAuthenticationToken_true")
    void supports_oauth2ClientAuthenticationToken_true() {
        assertTrue(provider.supports(OAuth2ClientAuthenticationToken.class));
    }

    @Test
    @DisplayName("supports_otherAuthenticationType_false")
    void supports_otherAuthenticationType_false() {
        assertFalse(provider.supports(OAuth2AuthorizationCodeAuthenticationToken.class));
        assertFalse(provider.supports(mock(Authentication.class).getClass()));
    }
}
