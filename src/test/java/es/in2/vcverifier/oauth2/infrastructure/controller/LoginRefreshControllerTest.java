package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestRefreshWorkflow;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginRefreshControllerTest {

    @InjectMocks
    private LoginRefreshController loginRefreshController;

    @Mock
    private AuthorizationRequestRefreshWorkflow authorizationRequestRefreshWorkflow;

    @Test
    @DisplayName("refresh() returns 200 with openid4vp URL when state is valid")
    void refresh_validState_shouldReturnOkWithAuthRequestUrl() {
        String state = "valid-state-1234";
        String expectedUrl = "openid4vp://?client_id=did%3Akey%3Az6Mk&request_uri=https%3A%2F%2Fverifier.example.com%2Foid4vp%2Fauth-request%2Fsome-nonce";
        when(authorizationRequestRefreshWorkflow.refresh(state))
                .thenReturn(new AuthorizationRequestRefreshWorkflow.Result(expectedUrl));

        ResponseEntity<Map<String, String>> response = loginRefreshController.refresh(state);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authRequest", expectedUrl);
    }

    @Test
    @DisplayName("refresh() returns 404 when session is not found or expired")
    void refresh_sessionNotFound_shouldReturn404() {
        String state = "expired-state-5678";
        when(authorizationRequestRefreshWorkflow.refresh(state))
                .thenThrow(new NoSuchElementException("Session not found"));

        ResponseEntity<Map<String, String>> response = loginRefreshController.refresh(state);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
