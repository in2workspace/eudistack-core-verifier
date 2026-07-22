package es.in2.vcverifier.oauth2.infrastructure.adapter;
import es.in2.vcverifier.shared.crypto.JWTService;

import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.JtiTokenCache;
import es.in2.vcverifier.oauth2.infrastructure.adapter.ClientAssertionValidationServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientAssertionValidationServiceImplTest {

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private JtiTokenCache jtiTokenCache;

    @Mock
    private JWTService jwtService;

    @InjectMocks
    private ClientAssertionValidationServiceImpl clientAssertionValidationService;

    @Test
    void validateClientAssertion_shouldReturnTrue() {
        String clientId = "1234";
        String authServer = "authorization-server";
        String jti = "jti";
        Payload payloadMock = mock(Payload.class);

        when(backendConfig.getUrl()).thenReturn(authServer);
        when(jwtService.extractClaimFromPayload(payloadMock,"iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(payloadMock,"sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(payloadMock,"aud")).thenReturn("authorization-server");
        when(jwtService.extractClaimFromPayload(payloadMock,"jti")).thenReturn(jti);
        when(jtiTokenCache.isJtiPresent(jti)).thenReturn(false);
        when(jwtService.extractExpirationFromPayload(payloadMock)).thenReturn(System.currentTimeMillis() / 1000 + 3600);

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, payloadMock);

        assertTrue(result);

    }

    @Test
    void verifyClientAssertionJWTClaims_invalidIssuer_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn("invalidClient");

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void verifyClientAssertionJWTClaims_invalidSubject_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn("invalidSubject");

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void verifyClientAssertionJWTClaims_invalidAudience_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn("wrongAudience");
        when(backendConfig.getUrl()).thenReturn("expectedAudience");

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void verifyClientAssertionJWTClaims_jtiAlreadyUsed_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn("expectedAudience");
        when(backendConfig.getUrl()).thenReturn("expectedAudience");
        when(jwtService.extractClaimFromPayload(mockPayload, "jti")).thenReturn("duplicate-jti");
        when(jtiTokenCache.isJtiPresent("duplicate-jti")).thenReturn(true);

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    /**
     * M2M audience tolerance: the canonical URL WITH the /verifier context-path is accepted.
     */
    @Test
    void m2mAudience_canonicalUrlWithContextPath_isAccepted() {
        givenRequestWithContextPath("/verifier");
        String clientId = "1234";
        String canonical = "https://verifier.dome-marketplace-lcl.org/verifier";
        String jti = "jti-m2m";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn(canonical);
        when(backendConfig.getUrl()).thenReturn(canonical);
        when(jwtService.extractClaimFromPayload(mockPayload, "jti")).thenReturn(jti);
        when(jtiTokenCache.isJtiPresent(jti)).thenReturn(false);
        when(jwtService.extractExpirationFromPayload(mockPayload)).thenReturn(System.currentTimeMillis() / 1000 + 3600);

        assertTrue(clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload));
    }

    /**
     * M2M audience tolerance: a legacy client that points at the clean public URL (WITHOUT the
     * /verifier context-path) is now accepted too, so M2M clients that never changed their URL
     * keep working after the context-path was introduced. Mirrors the authorization_code path.
     */
    @Test
    void m2mAudience_cleanUrlWithoutContextPath_isAccepted() {
        givenRequestWithContextPath("/verifier");
        String clientId = "1234";
        String canonical = "https://verifier.dome-marketplace-lcl.org/verifier";
        String cleanUrl = "https://verifier.dome-marketplace-lcl.org";
        String jti = "jti-m2m-clean";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn(cleanUrl);
        when(backendConfig.getUrl()).thenReturn(canonical);
        when(jwtService.extractClaimFromPayload(mockPayload, "jti")).thenReturn(jti);
        when(jtiTokenCache.isJtiPresent(jti)).thenReturn(false);
        when(jwtService.extractExpirationFromPayload(mockPayload)).thenReturn(System.currentTimeMillis() / 1000 + 3600);

        assertTrue(clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload));
    }

    /**
     * M2M audience tolerance does NOT open the door to any host: an unrelated audience is still
     * rejected even when the context-path is present.
     */
    @Test
    void m2mAudience_wrongHost_isRejectedEvenWithContextPath() {
        givenRequestWithContextPath("/verifier");
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn("https://evil.example.org");
        when(backendConfig.getUrl()).thenReturn("https://verifier.dome-marketplace-lcl.org/verifier");

        assertFalse(clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload));
    }

    @Test
    void verifyClientAssertionJWTClaims_expiredToken_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn("expectedAudience");
        when(backendConfig.getUrl()).thenReturn("expectedAudience");
        when(jwtService.extractExpirationFromPayload(mockPayload)).thenReturn(System.currentTimeMillis() / 1000 - 3600);

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    private void givenRequestWithContextPath(String contextPath) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath(contextPath);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
