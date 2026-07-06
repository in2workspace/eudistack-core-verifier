package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
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

    private static final String VERIFIER_URL = "https://verifier.example.com/verifier";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private BackendConfig backendConfig;

    private final Set<String> allowedClientsOrigins = new HashSet<>();

    private CustomErrorResponseHandler customErrorResponseHandler;

    @BeforeEach
    void setUp() {
        allowedClientsOrigins.clear();
        lenient().when(backendConfig.getStaticUrl()).thenReturn(VERIFIER_URL);
        customErrorResponseHandler = new CustomErrorResponseHandler(allowedClientsOrigins, backendConfig);
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
    void testOnAuthenticationFailure_WithVerifierOwnOrigin_ShouldRedirect() throws IOException {
        String redirectUri = "https://verifier.example.com/verifier/login?authRequest=openid4vp%3A%2F%2F&state=abc";

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
    void testOnAuthenticationFailure_WithVerifierOwnOriginErrorPage_ShouldRedirect() throws IOException {
        String redirectUri = "https://verifier.example.com/verifier/error?errorCode=abc&errorMessage=msg&clientUrl=x&originalRequestURL=y";

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
