package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit — verifies {@link SsoSessionLogoutFailureHandler} redirects to the resolved client's
 * {@code loginPageUri} with {@code error=session_expired} when one is known, falls back to a
 * registered {@code postLogoutRedirectUri} when there is no {@code loginPageUri}, and otherwise
 * falls back to the standard {@code OAuth2ErrorAuthenticationFailureHandler} (raw JSON) behavior
 * unchanged. The audit event must be published regardless of which path is taken.
 */
@ExtendWith(MockitoExtension.class)
class SsoSessionLogoutFailureHandlerTest {

    private static final String CLIENT_ID = "client-es01";
    private static final String LOGIN_PAGE_URI = "https://issuer.example.com/login";

    @Mock private SsoAuditPort auditPort;
    @Mock private RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthenticationException exception =
            new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint", null));

    @Nested
    @DisplayName("when the client has a loginPageUri configured")
    class WhenLoginPageIsKnown {

        @Test
        void onAuthenticationFailure_withClientIdAndLoginPageConfigured_redirectsWithSessionExpiredError() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithLoginPage(LOGIN_PAGE_URI));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isEqualTo(LOGIN_PAGE_URI + "?error=session_expired");
        }

        @Test
        void onAuthenticationFailure_withClientIdAndLoginPageConfigured_publishesRejectedAuditEvent() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithLoginPage(LOGIN_PAGE_URI));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            verify(auditPort).publish(argThat(event ->
                    event.getEventType() == SsoAuditEvent.EventType.SSO_LOGOUT_REJECTED
                            && CLIENT_ID.equals(event.getClientId())));
        }
    }

    @Nested
    @DisplayName("when the client has no loginPageUri but the request's post_logout_redirect_uri is registered")
    class WhenOnlyPostLogoutRedirectUriIsRegistered {

        private static final String POST_LOGOUT_REDIRECT_URI = "https://issuer.example.com/issuer/";

        @Test
        void onAuthenticationFailure_withRegisteredPostLogoutRedirectUri_redirectsWithSessionExpiredError() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            request.setParameter("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID))
                    .thenReturn(clientWithPostLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isEqualTo(POST_LOGOUT_REDIRECT_URI + "?error=session_expired");
        }

        @Test
        void onAuthenticationFailure_withUnregisteredPostLogoutRedirectUri_delegatesToStandardErrorHandler() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            request.setParameter("post_logout_redirect_uri", "https://not-registered.example.com/");
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID))
                    .thenReturn(clientWithPostLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
        }

        @Test
        void onAuthenticationFailure_withLoginPageAndRegisteredPostLogoutRedirectUriBoth_prefersLoginPage() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            request.setParameter("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RegisteredClient clientWithBoth = RegisteredClient.from(clientWithPostLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI))
                    .clientSettings(ClientSettings.builder()
                            .setting(CLIENT_SETTING_LOGIN_PAGE_URI, LOGIN_PAGE_URI)
                            .build())
                    .build();
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithBoth);
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isEqualTo(LOGIN_PAGE_URI + "?error=session_expired");
        }
    }

    @Nested
    @DisplayName("when no safe destination can be resolved")
    class WhenLoginPageIsUnknown {

        @Test
        void onAuthenticationFailure_withoutClientId_delegatesToStandardErrorHandler() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
        }

        @Test
        void onAuthenticationFailure_withUnknownClientId_delegatesToStandardErrorHandler() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
        }

        @Test
        void onAuthenticationFailure_withClientWithoutLoginPage_delegatesToStandardErrorHandler() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithoutLoginPage());
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("security / resilience")
    class Resilience {

        @Test
        void onAuthenticationFailure_whenAuditPortThrows_stillRedirectsToLoginPage() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            doThrow(new RuntimeException("audit sink unavailable")).when(auditPort).publish(any());
            when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithLoginPage(LOGIN_PAGE_URI));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isEqualTo(LOGIN_PAGE_URI + "?error=session_expired");
        }

        @Test
        void onAuthenticationFailure_whenRegisteredClientRepositoryThrows_delegatesToStandardErrorHandler() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID))
                    .thenThrow(new RuntimeException("client repository unavailable"));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
            verify(auditPort).publish(any());
        }

        @Test
        void onAuthenticationFailure_withNonHttpLoginPageUri_delegatesToStandardErrorHandlerInsteadOfThrowing() throws Exception {
            // Arrange
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("client_id", CLIENT_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            when(registeredClientRepository.findByClientId(CLIENT_ID))
                    .thenReturn(clientWithLoginPage("not-a-valid-http-uri"));
            SsoSessionLogoutFailureHandler handler =
                    new SsoSessionLogoutFailureHandler(auditPort, registeredClientRepository);

            // Act
            handler.onAuthenticationFailure(request, response, exception);

            // Assert
            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(response.getStatus()).isEqualTo(400);
            verify(auditPort).publish(any());
        }
    }

    private static RegisteredClient clientWithLoginPage(String loginPageUri) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client-es01.example.com/callback")
                .clientSettings(ClientSettings.builder()
                        .setting(CLIENT_SETTING_LOGIN_PAGE_URI, loginPageUri)
                        .build())
                .build();
    }

    private static RegisteredClient clientWithoutLoginPage() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client-es01.example.com/callback")
                .build();
    }

    private static RegisteredClient clientWithPostLogoutRedirectUri(String postLogoutRedirectUri) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client-es01.example.com/callback")
                .postLogoutRedirectUri(postLogoutRedirectUri)
                .build();
    }
}
