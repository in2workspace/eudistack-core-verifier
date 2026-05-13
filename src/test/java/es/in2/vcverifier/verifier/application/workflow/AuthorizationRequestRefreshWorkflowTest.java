package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.NoSuchElementException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestRefreshWorkflowTest {

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @Mock
    private RegisteredClientRepository registeredClientRepository;
    @Mock
    private AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    private AuthorizationRequestRefreshWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new AuthorizationRequestRefreshWorkflow(
                cacheStoreForOAuth2AuthorizationRequest,
                registeredClientRepository,
                authorizationRequestBuildWorkflow
        );
    }

    private OAuth2AuthorizationRequest buildAuthorizationRequest(String clientId, Set<String> scopes, String state) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .clientId(clientId)
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .redirectUri("https://verifier.example.com/callback")
                .scopes(scopes)
                .state(state)
                .build();
    }

    private RegisteredClient buildRegisteredClient(String clientId) {
        return RegisteredClient.withId("client-uuid-1234")
                .clientId(clientId)
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri("https://verifier.example.com/callback")
                .build();
    }

    @Test
    @DisplayName("refresh() returns openid4vp URL when state is valid")
    void refresh_validState_shouldReturnOpenid4vpUrl() {
        String state = "test-state-abc";
        String clientId = "did:key:z6MkTestKey";
        String expectedUrl = "openid4vp://?client_id=did%3Akey%3Az6MkTestKey&request_uri=https%3A%2F%2Fverifier.example.com%2Foid4vp%2Fauth-request%2Fsome-nonce";

        OAuth2AuthorizationRequest authorizationRequest = buildAuthorizationRequest(clientId, Set.of("openid", "learcredential"), state);
        RegisteredClient registeredClient = buildRegisteredClient(clientId);
        AuthorizationRequestBuildWorkflow.Result buildResult =
                new AuthorizationRequestBuildWorkflow.Result("signed-jwt", expectedUrl, "some-nonce", clientId);

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(authorizationRequest);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(eq(registeredClient), anyString(), eq(state)))
                .thenReturn(buildResult);

        AuthorizationRequestRefreshWorkflow.Result result = workflow.refresh(state);

        assertThat(result.openid4vpUrl()).isEqualTo(expectedUrl);
        verify(authorizationRequestBuildWorkflow).buildAuthorizationRequest(eq(registeredClient), anyString(), eq(state));
    }

    @Test
    @DisplayName("refresh() propagates NoSuchElementException when session is not found in cache")
    void refresh_sessionNotFound_shouldPropagateNoSuchElementException() {
        String state = "expired-state-xyz";
        when(cacheStoreForOAuth2AuthorizationRequest.get(state))
                .thenThrow(new NoSuchElementException("Session not found"));

        assertThatThrownBy(() -> workflow.refresh(state))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    @DisplayName("refresh() throws NoSuchElementException when registered client is not found")
    void refresh_clientNotFound_shouldThrowNoSuchElementException() {
        String state = "test-state-def";
        String clientId = "did:key:z6MkUnknown";

        OAuth2AuthorizationRequest authorizationRequest = buildAuthorizationRequest(clientId, Set.of("openid"), state);
        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(authorizationRequest);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        assertThatThrownBy(() -> workflow.refresh(state))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining(clientId);
    }
}
