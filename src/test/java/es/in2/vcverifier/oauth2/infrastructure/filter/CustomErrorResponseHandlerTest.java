package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomErrorResponseHandlerTest {

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
        lenient().when(backendConfig.getTrustedVerifierOrigins()).thenReturn(Set.of("https://verifier.example.com"));
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

    @Test
    void testOnAuthenticationFailure_WithMultipleTrustedVerifierOrigins_ShouldRedirect() throws IOException {
        when(backendConfig.getTrustedVerifierOrigins())
                .thenReturn(Set.of("https://verifier.example.com", "https://kpmg.eudistack.net"));
        String redirectUri = "https://kpmg.eudistack.net/login?state=abc";

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
    void testOnAuthenticationFailure_WithVerifierOriginDifferentCaseAndDefaultPort_ShouldRedirect() throws IOException {
        String redirectUri = "https://Verifier.Example.com:443/login?state=abc";

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
    void testOnAuthenticationFailure_WithAllowedClientOriginDifferentCase_ShouldRedirect() throws IOException {
        allowedClientsOrigins.add("https://external-rp.example.com");
        String redirectUri = "https://External-RP.Example.com/login";

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
    void testOnAuthenticationFailure_WithUppercaseHttpsScheme_ShouldRedirect() throws IOException {
        String redirectUri = "HTTPS://verifier.example.com/login?state=abc";

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

    // ---- EUD-252: browser-binding cookie on the login-page redirect ----

    private static final String BINDING_VALUE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void onAuthenticationFailure_loginPageRedirectWithPendingBinding_emitsHostBindingCookie() throws IOException {
        // Given: the converter bound the login to this browser (SSO tenant)
        String redirectUri = "https://verifier.example.com/login?state=abc";
        when(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).thenReturn(BINDING_VALUE);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error("required_external_user_authentication", "Redirection required", redirectUri), null);

        // When
        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        // Then: __Host- cookie with the mandated attributes, then the redirect
        ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Set-Cookie"), header.capture());
        assertThat(header.getValue())
                .startsWith("__Host-sso-tx=" + BINDING_VALUE)
                .contains("Path=/", "Max-Age=600", "Secure", "HttpOnly", "SameSite=Lax")
                .doesNotContain("Domain=");
        verify(response).sendRedirect(redirectUri);
    }

    @Test
    void onAuthenticationFailure_loginPageRedirectWithoutPendingBinding_emitsNoCookie() throws IOException {
        // Given: SSO-disabled tenant → the converter set no binding
        String redirectUri = "https://verifier.example.com/login?state=abc";
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error("required_external_user_authentication", "Redirection required", redirectUri), null);

        // When
        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        // Then
        verify(response, never()).addHeader(eq("Set-Cookie"), anyString());
        verify(response).sendRedirect(redirectUri);
    }

    @Test
    void onAuthenticationFailure_loginRequiredWithPendingBinding_emitsNoCookie() throws IOException {
        // Given: an OIDC error redirect to the RP, not the login page
        allowedClientsOrigins.add("https://client.example.com");
        String redirectUri = "https://client.example.com/callback?error=login_required";
        lenient().when(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).thenReturn(BINDING_VALUE);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error("login_required", null, redirectUri), null);

        // When
        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        // Then
        verify(response, never()).addHeader(eq("Set-Cookie"), anyString());
        verify(response).sendRedirect(redirectUri);
    }

    @Test
    void onAuthenticationFailure_untrustedLoginPageWithPendingBinding_emitsNoCookie() throws IOException {
        // Given: SEC-S7 open-redirect guard rejects the target
        String redirectUri = "https://evil.example.org/login";
        lenient().when(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).thenReturn(BINDING_VALUE);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error("required_external_user_authentication", "Redirection required", redirectUri), null);

        // When
        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        // Then
        verify(response, never()).addHeader(eq("Set-Cookie"), anyString());
        verify(response).sendError(eq(400), anyString());
    }
}
