package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.exception.LoginCompletionUnavailableException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Supplier;

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
    // Base64-encoded, as a wallet sends it; its JWT payload carries the subject "test-holder".
    private static final String VP_TOKEN = Base64.getEncoder().encodeToString(
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig".getBytes(StandardCharsets.UTF_8));

    @Test
    void handleAuthResponse_sendsWorkflowRedirectOverSse() {
        // Given: the workflow decides where the browser goes (RP URL or close URL)
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        AuthResponseResult result = result("bind-hash");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN, "tenant-a")).thenReturn(result);
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq("tenant-a"), eq(result), any(), anyString()))
                .thenReturn("https://tenant-a.example.com/verifier/api/login/complete?h=one-time-handle");

        // When
        oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request);

        // Then: the wallet's tenant is checked by the processor; the browser gets the workflow's URL
        verify(sseEmitterStore).send(STATE, "https://tenant-a.example.com/verifier/api/login/complete?h=one-time-handle");
        verify(sseEmitterStore, never()).sendValidationFailed(anyString(), anyString(), anyString());
    }

    @Test
    void handleAuthResponse_subjectSupplier_extractsRawSubFromVpToken() {
        // Given
        when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn("tenant-a");
        when(authorizationResponseProcessorService.handleAuthResponse(STATE, VP_TOKEN, "tenant-a")).thenReturn(result("h"));
        ArgumentCaptor<Supplier<String>> subject = ArgumentCaptor.captor();
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq("tenant-a"), any(), subject.capture(), anyString()))
                .thenReturn("url");

        // When
        oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request);

        // Then: the subject is read from the VP token payload
        assertEquals("test-holder", subject.getValue().get());
    }

    @Test
    void handleAuthResponse_subjectSupplier_noUsableSubject_throwsIllegalState() {
        // Given: VP token whose payload has neither sub nor iss
        String vpTokenNoSub = Base64.getEncoder().encodeToString(
                "eyJhbGciOiJub25lIn0.e30.fakesig".getBytes(StandardCharsets.UTF_8));
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(vpTokenNoSub), any()))
                .thenReturn(result("h"));
        ArgumentCaptor<Supplier<String>> subject = ArgumentCaptor.captor();
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(any(), any(), subject.capture(), anyString()))
                .thenReturn("url");

        // When
        oid4vpController.handleAuthResponse(STATE, vpTokenNoSub, request);

        // Then: the workflow is the one deciding what an unusable subject means (B5)
        Supplier<String> holderSubject = subject.getValue();
        assertThrows(IllegalStateException.class, holderSubject::get);
    }

    @ParameterizedTest
    @ValueSource(strings = {"~", "~~", "~~~"})
    void handleAuthResponse_subjectSupplier_degenerateSdJwtSeparators_throwsIllegalState(String degenerateToken) {
        // Given: String.split("~") would return an empty array for these tokens
        String vpToken = Base64.getEncoder().encodeToString(degenerateToken.getBytes(StandardCharsets.UTF_8));
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(vpToken), any()))
                .thenReturn(result("h"));
        ArgumentCaptor<Supplier<String>> subject = ArgumentCaptor.captor();
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(any(), any(), subject.capture(), anyString()))
                .thenReturn("url");

        oid4vpController.handleAuthResponse(STATE, vpToken, request);

        Supplier<String> holderSubject = subject.getValue();
        assertThrows(IllegalStateException.class, holderSubject::get);
    }

    @Test
    void handleAuthResponse_subjectSupplier_sdJwtWithKbJwt_fallsBackToKbJwtIssuer() {
        // Given: issuer-signed part without sub/iss, holder only identified by the KB-JWT iss
        String empty = b64Url("{}");
        String kbJwt = b64Url("{\"alg\":\"none\"}") + "." + b64Url("{\"iss\":\"holder-kb\"}") + ".sig";
        String sdJwt = b64Url("{\"alg\":\"none\"}") + "." + empty + ".sig~disclosure~" + kbJwt;
        String vpToken = Base64.getEncoder().encodeToString(sdJwt.getBytes(StandardCharsets.UTF_8));
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(vpToken), any()))
                .thenReturn(result("h"));
        ArgumentCaptor<Supplier<String>> subject = ArgumentCaptor.captor();
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(any(), any(), subject.capture(), anyString()))
                .thenReturn("url");

        oid4vpController.handleAuthResponse(STATE, vpToken, request);

        assertEquals("holder-kb", subject.getValue().get());
    }

    @Test
    void handleAuthResponse_subjectSupplier_sdJwtWithoutKbJwt_throwsIllegalState() {
        // Given: trailing "~" means no KB-JWT, and the issuer-signed part carries no sub/iss
        String sdJwt = b64Url("{\"alg\":\"none\"}") + "." + b64Url("{}") + ".sig~disclosure~";
        String vpToken = Base64.getEncoder().encodeToString(sdJwt.getBytes(StandardCharsets.UTF_8));
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(vpToken), any()))
                .thenReturn(result("h"));
        ArgumentCaptor<Supplier<String>> subject = ArgumentCaptor.captor();
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(any(), any(), subject.capture(), anyString()))
                .thenReturn("url");

        oid4vpController.handleAuthResponse(STATE, vpToken, request);

        Supplier<String> holderSubject = subject.getValue();
        assertThrows(IllegalStateException.class, holderSubject::get);
    }

    private static String b64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void handleAuthResponse_loginCompletionUnavailable_notifiesBrowserAndNeverSendsCode() {
        // Given: bound login whose close step can't be offered (workflow already revoked + audited)
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(VP_TOKEN), any()))
                .thenReturn(result("bind-hash"));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(any(), any(), any(), anyString()))
                .thenThrow(new LoginCompletionUnavailableException("unavailable"));

        // When / Then: fail closed
        assertThrows(LoginCompletionUnavailableException.class,
                () -> oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request));
        verify(sseEmitterStore).sendValidationFailed(eq(STATE), eq("LOGIN_COMPLETION_UNAVAILABLE"), anyString());
        verify(sseEmitterStore, never()).send(anyString(), anyString());
    }

    @Test
    void handleAuthResponse_processingFailure_auditsAndRethrows() {
        // Given
        when(authorizationResponseProcessorService.handleAuthResponse(eq(STATE), eq(VP_TOKEN), any()))
                .thenThrow(new IllegalStateException("vp invalid"));

        // When / Then (ES-01)
        assertThrows(IllegalStateException.class, () -> oid4vpController.handleAuthResponse(STATE, VP_TOKEN, request));
        verify(ssoAuditPort).publish(argThat(e -> e.getEventType() == SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED));
        verifyNoInteractions(sseEmitterStore, ssoLoginCompletionWorkflow);
    }

    private static AuthResponseResult result(String bindingHash) {
        return new AuthResponseResult(null, RP_URL, "https://rp.example.com/cb", STATE, "client-a", "the-code",
                bindingHash, "https://tenant-a.example.com/verifier");
    }

}
