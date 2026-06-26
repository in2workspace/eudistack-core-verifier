package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
    private SsoSessionAuthenticationSuccessHandler ssoSessionHandler;

    @Mock
    private SsoAuditPort ssoAuditPort;

    @Spy
    ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;





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

    @Test
    void handleAuthResponse_validParameters_shouldInvokeService() throws Exception {
        String state = "validState";
        // The controller receives the vp_token Base64-encoded (mirrors what a wallet sends)
        String vpToken = Base64.getEncoder().encodeToString(
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig"
                        .getBytes(StandardCharsets.UTF_8));

        oid4vpController.handleAuthResponse(state, vpToken, request, response);

        verify(authorizationResponseProcessorService).handleAuthResponse(state, vpToken);
        verify(ssoSessionHandler).onAuthenticationSuccess(eq(request), eq(response), any());
    }

}
