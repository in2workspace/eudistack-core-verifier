package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.model.PendingSsoLogin;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class Oid4vpControllerTest {

    @InjectMocks
    private Oid4vpController oid4vpController;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private AuthorizationResponseProcessorService authorizationResponseProcessorService;

    @Mock
    private SsoLoginCompletionWorkflow ssoLoginCompletionWorkflow;

    @Mock
    private SseEmitterStore sseEmitterStore;

    @Mock
    private SsoAuditPort ssoAuditPort;

    @Spy
    ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private HttpServletRequest request;






    @Test
    void getAuthorizationRequest_validId_shouldReturnJwt() {
        String id = "validId";
        String expectedJwt = "sampleJwt";
        AuthorizationRequestJWT mockAuthRequestJWT = Mockito.mock(AuthorizationRequestJWT.class);

        when(cacheStoreForAuthorizationRequestJWT.get(id)).thenReturn(mockAuthRequestJWT);
        when(mockAuthRequestJWT.authRequest()).thenReturn(expectedJwt);

        String resultJwt = oid4vpController.getAuthorizationRequest(id);

        assertEquals(expectedJwt, resultJwt);
        Mockito.verify(cacheStoreForAuthorizationRequestJWT).delete(id);
    }

    @Test
    void getAuthorizationRequest_invalidId_shouldThrowResourceNotFoundException() {
        String id = "invalidId";

        AuthorizationRequestJWT authorizationRequestJWT = AuthorizationRequestJWT.builder().authRequest(null).build();
        when(cacheStoreForAuthorizationRequestJWT.get(id)).thenReturn(authorizationRequestJWT);

        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () ->
                oid4vpController.getAuthorizationRequest(id)
        );

        assertEquals("JWT not found for id: " + id, exception.getMessage());
    }

    private static final String STATE = "validState";
    private static final String RP_URL = "https://rp.example.com/cb?code=the-code&state=validState";
    // The controller receives the vp_token Base64-encoded (mirrors what a wallet sends); payload {"sub":"test-holder"}
    private static final String VP_TOKEN = Base64.getEncoder().encodeToString(
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig".getBytes(StandardCharsets.UTF_8));

    @Test
    void handleAuthResponse_unboundLogin_sendsRpRedirectOverSse() {
        // Given: SSO-disabled tenant / no browser binding
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN)).thenReturn(result(null));
        when(ssoLoginCompletionWorkflow.requiresBrowserBinding("tenant-a", null)).thenReturn(false);

        // When
        oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request);

        // Then: unchanged legacy behaviour, nothing parked
        verify(sseEmitterStore).send(STATE, RP_URL);
        verify(ssoLoginCompletionWorkflow, never()).registerPendingLogin(any());
    }

    @Test
    void handleAuthResponse_ssoBoundLogin_parksLoginAndSendsCloseUrl() {
        // Given: SSO tenant, login bound to the browser at /authorize
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN)).thenReturn(result("bind-hash"));
        when(ssoLoginCompletionWorkflow.requiresBrowserBinding("tenant-a", "bind-hash")).thenReturn(true);
        when(ssoLoginCompletionWorkflow.registerPendingLogin(any())).thenReturn("one-time-handle");

        // When
        oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request);

        // Then: the browser gets the close URL on the /authorize host, never the code
        verify(sseEmitterStore).send(STATE, "https://tenant-a.example.com/verifier/api/login/complete?h=one-time-handle");
        ArgumentCaptor<PendingSsoLogin> pending = ArgumentCaptor.forClass(PendingSsoLogin.class);
        verify(ssoLoginCompletionWorkflow).registerPendingLogin(pending.capture());
        assertEquals("tenant-a", pending.getValue().tenant());
        assertEquals("test-holder", pending.getValue().holderSubject());
        assertEquals("bind-hash", pending.getValue().browserBindingHash());
        assertEquals("the-code", pending.getValue().authorizationCode());
        assertEquals(RP_URL, pending.getValue().redirectUrl());
    }

    @Test
    void handleAuthResponse_ssoBoundLoginWithoutUsableSubject_completesWithoutSso() {
        // Given: VP token whose payload has neither sub nor iss
        String vpTokenNoSub = Base64.getEncoder().encodeToString(
                "eyJhbGciOiJub25lIn0.e30.fakesig".getBytes(StandardCharsets.UTF_8));
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, vpTokenNoSub)).thenReturn(result("bind-hash"));
        when(ssoLoginCompletionWorkflow.requiresBrowserBinding("tenant-a", "bind-hash")).thenReturn(true);

        // When
        oid4vpController.handleAuthResponse(STATE, vpTokenNoSub, request);

        // Then: login still completes (RP URL), no SSO, audited
        verify(sseEmitterStore).send(STATE, RP_URL);
        verify(ssoLoginCompletionWorkflow, never()).registerPendingLogin(any());
        verify(ssoAuditPort).publish(argThat(e -> e.getEventType() == SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED
                && "no_usable_subject".equals(e.getReason())));
    }

    @Test
    void handleAuthResponse_ssoRoutingFails_stillSendsRpRedirect() {
        // Given: tenant SSO config unavailable while routing the browser
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN)).thenReturn(result("bind-hash"));
        when(ssoLoginCompletionWorkflow.requiresBrowserBinding("tenant-a", "bind-hash"))
                .thenThrow(new RuntimeException("config store down"));

        // When
        oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request);

        // Then: fail-open — the verified login completes without SSO, and it is audited
        verify(sseEmitterStore).send(STATE, RP_URL);
        verify(ssoAuditPort).publish(argThat(e -> e.getEventType() == SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED
                && "sso_routing_failed".equals(e.getReason())));
    }

    @Test
    void handleAuthResponse_processingFailure_auditsAndRethrows() {
        // Given
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN))
                .thenThrow(new IllegalStateException("vp invalid"));

        // When / Then (ES-01)
        assertThrows(IllegalStateException.class, () -> oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request));
        verify(ssoAuditPort).publish(argThat(e -> e.getEventType() == SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED));
        verifyNoInteractions(sseEmitterStore);
    }

    private static AuthResponseResult result(String bindingHash) {
        return new AuthResponseResult(null, RP_URL, "https://rp.example.com/cb", STATE, "client-a", "the-code",
                bindingHash, "https://tenant-a.example.com/verifier");
    }

}
