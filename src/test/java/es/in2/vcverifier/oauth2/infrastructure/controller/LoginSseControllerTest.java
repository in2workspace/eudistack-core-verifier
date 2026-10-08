package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.oauth2.application.workflow.AbortLoginWorkflow;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.BackendConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginSseControllerTest {

    @Mock
    private SseEmitterStore sseEmitterStore;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private AbortLoginWorkflow abortLoginWorkflow;

    @InjectMocks
    private LoginSseController controller;

    @Test
    void subscribe_usesTheLoginEventStreamTimeout() {
        when(backendConfig.getLoginEventStreamTimeoutSeconds()).thenReturn(150L);

        controller.subscribe("s1");

        verify(sseEmitterStore).create("s1", 150_000L);
    }

    @Test
    void abort_pendingLogin_returnsRedirectUrl() {
        String redirectUrl = "https://rp.example.com/cb?error=access_denied&error_description=login_timeout&state=s1";
        when(abortLoginWorkflow.abort("s1")).thenReturn(Optional.of(redirectUrl));

        ResponseEntity<LoginSseController.AbortLoginResponse> response = controller.abort("s1");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(new LoginSseController.AbortLoginResponse(redirectUrl));
    }

    @Test
    void abort_unknownState_returnsNotFound() {
        when(abortLoginWorkflow.abort("unknown")).thenReturn(Optional.empty());

        ResponseEntity<LoginSseController.AbortLoginResponse> response = controller.abort("unknown");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNull();
    }
}
