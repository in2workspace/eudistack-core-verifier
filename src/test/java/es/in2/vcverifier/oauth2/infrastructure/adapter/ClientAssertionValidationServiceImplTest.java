package es.in2.vcverifier.oauth2.infrastructure.adapter;
import es.in2.vcverifier.shared.crypto.JWTService;

import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.config.VerifierConfig;
import es.in2.vcverifier.shared.config.JtiTokenCache;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientAssertionValidationServiceImplTest {

    @Mock
    private VerifierConfig verifierConfig;

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

        when(verifierConfig.getUrl()).thenReturn(authServer);
        when(jwtService.extractClaimFromPayload(payloadMock, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(payloadMock, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(payloadMock, "aud")).thenReturn("authorization-server");
        when(jwtService.extractClaimFromPayload(payloadMock, "jti")).thenReturn(jti);
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
        when(verifierConfig.getUrl()).thenReturn("expectedAudience");

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
        when(verifierConfig.getUrl()).thenReturn("expectedAudience");
        when(jwtService.extractClaimFromPayload(mockPayload, "jti")).thenReturn("duplicate-jti");
        when(jtiTokenCache.isJtiPresent("duplicate-jti")).thenReturn(true);

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void verifyClientAssertionJWTClaims_expiredToken_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.extractClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.extractClaimFromPayload(mockPayload, "aud")).thenReturn("expectedAudience");
        when(verifierConfig.getUrl()).thenReturn("expectedAudience");
        when(jwtService.extractExpirationFromPayload(mockPayload)).thenReturn(System.currentTimeMillis() / 1000 - 3600);

        boolean result = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }
}
