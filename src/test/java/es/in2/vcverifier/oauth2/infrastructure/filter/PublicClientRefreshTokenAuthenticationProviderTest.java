package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PublicClientRefreshTokenAuthenticationProviderTest {

    private static final String CLIENT_ID = "vc-auth-client-sandbox";

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    private PublicClientRefreshTokenAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository);
    }

    private RegisteredClient publicClient(String clientId) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://example.com/callback")
                .build();
    }

    @Test
    void authenticate_differentAuthenticationMethod_returnsNull() {
        OAuth2ClientAuthenticationToken unrelatedToken =
                new OAuth2ClientAuthenticationToken(CLIENT_ID, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret", null);

        assertNull(provider.authenticate(unrelatedToken));
    }

    @Test
    void authenticate_clientNoLongerRegistered_returnsNull() {
        OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
                CLIENT_ID, PublicClientRefreshTokenAuthenticationConverter.PUBLIC_CLIENT_REFRESH_TOKEN_METHOD, null, null);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);

        assertNull(provider.authenticate(token));
    }

    @Test
    void authenticate_validPublicClient_returnsAuthenticatedToken() {
        OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
                CLIENT_ID, PublicClientRefreshTokenAuthenticationConverter.PUBLIC_CLIENT_REFRESH_TOKEN_METHOD, null, null);
        RegisteredClient registeredClient = publicClient(CLIENT_ID);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);

        Authentication result = provider.authenticate(token);

        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken authenticated = (OAuth2ClientAuthenticationToken) result;
        assertEquals(registeredClient, authenticated.getPrincipal());
        assertTrue(authenticated.isAuthenticated());
    }

    @Test
    void supports_oAuth2ClientAuthenticationToken_returnsTrue() {
        assertTrue(provider.supports(OAuth2ClientAuthenticationToken.class));
    }

    @Test
    void supports_unrelatedType_returnsFalse() {
        assertEquals(false, provider.supports(String.class));
    }
}
