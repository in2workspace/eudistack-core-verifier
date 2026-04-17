package es.in2.vcverifier.oauth2.infrastructure.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomErrorResponseHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private final Set<String> allowedClientsOrigins = new HashSet<>();

    private CustomErrorResponseHandler customErrorResponseHandler;

    @BeforeEach
    void setUp() {
        allowedClientsOrigins.clear();
        customErrorResponseHandler = new CustomErrorResponseHandler(allowedClientsOrigins);
    }

    @Test
    void testOnAuthenticationFailure_WithRequiredExternalUserAuthenticationError_ShouldRedirect() throws IOException {
        allowedClientsOrigins.add("https://example.com");
        String redirectUri = "https://example.com/login";

        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                redirectUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testOnAuthenticationFailure_WithInvalidClientAuthenticationError_ShouldRedirect() throws IOException {
        allowedClientsOrigins.add("https://example.com");
        String redirectUri = "https://example.com/error";

        OAuth2Error oauth2Error = new OAuth2Error(
                "invalid_client_authentication",
                "Invalid client authentication",
                redirectUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testOnAuthenticationFailure_WithOAuth2Exception_OtherErrorCode_ShouldSendError() throws IOException {
        OAuth2Error oauth2Error = new OAuth2Error("invalid_request", "Invalid request", null);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithOtherAuthenticationException_ShouldSendError() throws IOException {
        AuthenticationException exception = mock(AuthenticationException.class);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithUntrustedRedirectUri_ShouldSendError() throws IOException {
        allowedClientsOrigins.add("https://example.com");
        String untrustedUri = "https://evil.com/phishing";

        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                untrustedUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithAllowedClientOrigin_ShouldRedirect() throws IOException {
        allowedClientsOrigins.add("https://external-rp.example.com");
        String redirectUri = "https://external-rp.example.com/login?foo=bar";

        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                redirectUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testOnAuthenticationFailure_WithUnregisteredClientOrigin_ShouldBlock() throws IOException {
        allowedClientsOrigins.add("https://legit.example.com");
        String untrustedUri = "https://evil.com/phishing";

        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                untrustedUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithHttpClientOrigin_ShouldBlock() throws IOException {
        allowedClientsOrigins.add("http://insecure.example.com");
        String httpUri = "http://insecure.example.com/login";

        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                httpUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }
}
