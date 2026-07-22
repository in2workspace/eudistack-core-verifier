package es.in2.vcverifier.oauth2.infrastructure.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UnregisteredM2MClientAuthenticationConverterTest {

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private HttpServletRequest request;

    private UnregisteredM2MClientAuthenticationConverter converter;

    private void setUp() {
        converter = new UnregisteredM2MClientAuthenticationConverter(registeredClientRepository);
    }

    @Test
    @DisplayName("convert_unregisteredClientCredentialsGrant_returnsUnauthenticatedToken")
    void convert_unregisteredClientCredentialsGrant_returnsUnauthenticatedToken() {
        setUp();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("unregistered-machine-client");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION)).thenReturn("assertion-jwt");
        when(registeredClientRepository.findByClientId("unregistered-machine-client")).thenReturn(null);

        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put(OAuth2ParameterNames.CLIENT_ID, new String[]{"unregistered-machine-client"});
        parameterMap.put(OAuth2ParameterNames.CLIENT_ASSERTION, new String[]{"assertion-jwt"});
        when(request.getParameterMap()).thenReturn(parameterMap);

        Authentication result = converter.convert(request);

        assertNotNull(result);
        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) result;
        assertEquals("unregistered-machine-client", token.getPrincipal());
        assertEquals("assertion-jwt", token.getCredentials());
        assertEquals(UnregisteredM2MClientAuthenticationConverter.UNREGISTERED_VC_METHOD, token.getClientAuthenticationMethod());
        assertFalse(token.isAuthenticated());
    }

    @Test
    @DisplayName("convert_clientAlreadyRegistered_returnsNullDeferringToSpringBuiltins")
    void convert_clientAlreadyRegistered_returnsNullDeferringToSpringBuiltins() {
        setUp();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("registered-client");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION)).thenReturn("assertion-jwt");
        RegisteredClient existingClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId("registered-client")).thenReturn(existingClient);

        Authentication result = converter.convert(request);

        assertNull(result);
    }

    @Test
    @DisplayName("convert_missingClientAssertion_returnsNull")
    void convert_missingClientAssertion_returnsNull() {
        setUp();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some-client");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION)).thenReturn(null);

        Authentication result = converter.convert(request);

        assertNull(result);
        verify(registeredClientRepository, never()).findByClientId(anyString());
    }

    @Test
    @DisplayName("convert_missingClientId_returnsNull")
    void convert_missingClientId_returnsNull() {
        setUp();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION)).thenReturn("assertion-jwt");

        Authentication result = converter.convert(request);

        assertNull(result);
        verify(registeredClientRepository, never()).findByClientId(anyString());
    }

    @Test
    @DisplayName("convert_nonClientCredentialsGrant_returnsNull")
    void convert_nonClientCredentialsGrant_returnsNull() {
        setUp();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn("authorization_code");

        Authentication result = converter.convert(request);

        assertNull(result);
        verify(registeredClientRepository, never()).findByClientId(anyString());
    }

    @Test
    @DisplayName("convert_nonPostMethod_returnsNull")
    void convert_nonPostMethod_returnsNull() {
        setUp();
        when(request.getMethod()).thenReturn("GET");

        Authentication result = converter.convert(request);

        assertNull(result);
        verifyNoInteractions(registeredClientRepository);
    }
}
