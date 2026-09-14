package es.in2.vcverifier.oauth2.infrastructure.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PublicClientRefreshTokenAuthenticationConverterTest {

    private static final String CLIENT_ID = "vc-auth-client-sandbox";

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    private PublicClientRefreshTokenAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new PublicClientRefreshTokenAuthenticationConverter(registeredClientRepository);
    }

    private HttpServletRequest requestFor(String method, String grantType, String clientId) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        if (grantType != null) {
            when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(grantType);
        }
        if (clientId != null) {
            when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        }
        return request;
    }

    private RegisteredClient publicClient(String clientId) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://example.com/callback")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();
    }

    @Test
    void convert_notPost_returnsNull() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");

        assertNull(converter.convert(request));
    }

    @Test
    void convert_notRefreshTokenGrant_returnsNull() {
        HttpServletRequest request = requestFor("POST", "authorization_code", CLIENT_ID);

        assertNull(converter.convert(request));
    }

    @Test
    void convert_missingClientId_returnsNull() {
        HttpServletRequest request = requestFor("POST", "refresh_token", null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("");

        assertNull(converter.convert(request));
    }

    @Test
    void convert_unknownClient_returnsNull() {
        HttpServletRequest request = requestFor("POST", "refresh_token", CLIENT_ID);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);

        assertNull(converter.convert(request));
    }

    @Test
    void convert_confidentialClient_returnsNull() {
        HttpServletRequest request = requestFor("POST", "refresh_token", CLIENT_ID);
        RegisteredClient confidentialClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(confidentialClient);

        assertNull(converter.convert(request));
    }

    @Test
    void convert_publicClientRefreshTokenRequest_returnsAuthenticationToken() {
        HttpServletRequest request = requestFor("POST", "refresh_token", CLIENT_ID);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(publicClient(CLIENT_ID));

        Authentication result = converter.convert(request);

        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) result;
        assertEquals(CLIENT_ID, token.getPrincipal());
        assertEquals(PublicClientRefreshTokenAuthenticationConverter.PUBLIC_CLIENT_REFRESH_TOKEN_METHOD,
                token.getClientAuthenticationMethod());
        assertEquals(false, token.isAuthenticated());
    }
}
