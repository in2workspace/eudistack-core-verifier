package es.in2.vcverifier.sso.infrastructure.controller;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.model.PendingSsoLogin;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoLoginCompletionControllerTest {

    private static final String RP_URL = "https://rp.example.com/cb?code=c&state=st";

    @Mock private SsoLoginCompletionWorkflow workflow;
    @Mock private SsoBrowserBindingCookie bindingCookie;
    @Mock private SsoSessionAuthenticationSuccessHandler ssoSessionHandler;

    @InjectMocks private SsoLoginCompletionController controller;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, "tenant-a");
        response = new MockHttpServletResponse();
    }

    @Test
    void complete_bindingVerified_establishesSessionAndRedirectsToRp() throws Exception {
        // Given
        when(bindingCookie.readValue(request)).thenReturn(Optional.of("bv"));
        when(workflow.complete("h", "bv", "tenant-a"))
                .thenReturn(new SsoLoginCompletionWorkflow.Outcome.Completed(pending()));

        // When
        controller.complete("h", request, response);

        // Then: same principal map as the pre-EUD-252 establishment path
        ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(ssoSessionHandler).onAuthenticationSuccess(eq(request), eq(response), auth.capture());
        Map<?, ?> principal = (Map<?, ?>) auth.getValue().getPrincipal();
        assertThat(principal.get("tenant")).isEqualTo("tenant-a");
        assertThat(principal.get("holderHash")).isEqualTo("raw-sub");
        assertThat(principal.get("tenantSlug")).isEqualTo("tenant-a");
        assertThat(response.getRedirectedUrl()).isEqualTo(RP_URL);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void complete_establishmentThrows_stillRedirectsToRp() throws Exception {
        // Given: fail-open — SSO establishment failure must not block the verified login
        when(bindingCookie.readValue(request)).thenReturn(Optional.of("bv"));
        when(workflow.complete("h", "bv", "tenant-a"))
                .thenReturn(new SsoLoginCompletionWorkflow.Outcome.Completed(pending()));
        doThrow(new IllegalStateException("db down"))
                .when(ssoSessionHandler).onAuthenticationSuccess(any(), any(), any());

        // When
        controller.complete("h", request, response);

        // Then
        assertThat(response.getRedirectedUrl()).isEqualTo(RP_URL);
    }

    @Test
    void complete_bindingRejected_redirectsWithErrorAndNoSession() throws Exception {
        // Given
        when(bindingCookie.readValue(request)).thenReturn(Optional.empty());
        when(workflow.complete("h", null, "tenant-a"))
                .thenReturn(new SsoLoginCompletionWorkflow.Outcome.Rejected(
                        "https://rp.example.com/cb?error=access_denied&state=st"));

        // When
        controller.complete("h", request, response);

        // Then
        verify(ssoSessionHandler, never()).onAuthenticationSuccess(any(), any(), any());
        assertThat(response.getRedirectedUrl()).isEqualTo("https://rp.example.com/cb?error=access_denied&state=st");
        assertThat(response.getHeader("Set-Cookie")).isNull();
    }

    @Test
    void complete_unknownHandle_returns400WithoutRedirect() throws Exception {
        // Given
        when(bindingCookie.readValue(request)).thenReturn(Optional.of("bv"));
        when(workflow.complete("h", "bv", "tenant-a")).thenReturn(new SsoLoginCompletionWorkflow.Outcome.Unknown());

        // When
        controller.complete("h", request, response);

        // Then
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getRedirectedUrl()).isNull();
        verify(ssoSessionHandler, never()).onAuthenticationSuccess(any(), any(), any());
    }

    private static PendingSsoLogin pending() {
        return new PendingSsoLogin("tenant-a", "raw-sub", "client-a", null, RP_URL,
                "https://rp.example.com/cb", "st", "hash", "c");
    }
}
