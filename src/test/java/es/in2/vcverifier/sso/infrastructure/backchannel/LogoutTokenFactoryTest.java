package es.in2.vcverifier.sso.infrastructure.backchannel;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.sso.domain.model.LogoutToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * US-06 (AC-04): {@code LogoutTokenFactory.build()} produce un payload de claims completo
 * conforme a OIDC Back-Channel Logout 1.0 §2.4 y delega la firma a {@link JWTService}
 * (mismo signer que el resto de tokens del Verifier — no reimplementa ECDSA).
 */
@ExtendWith(MockitoExtension.class)
class LogoutTokenFactoryTest {

    @Mock
    private JWTService jwtService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void build_producesValidBackchannelToken() {
        LogoutTokenFactory factory = new LogoutTokenFactory(jwtService, objectMapper);

        LogoutToken token = LogoutToken.of(
                "https://idp.dome.example.com",
                "callee-client-b",
                "opaque-session-id-123",
                Instant.parse("2026-01-15T10:00:00Z"),
                "jti-abc-123"
        );

        when(jwtService.issueJWT(anyString())).thenReturn("signed.jwt.value");

        String result = factory.build(token);

        assertEquals("signed.jwt.value", result);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWT(payloadCaptor.capture());
        String payload = payloadCaptor.getValue();

        // AC-04: claims completos
        assertTrue(payload.contains("\"iss\":\"https://idp.dome.example.com\""));
        assertTrue(payload.contains("\"aud\":\"callee-client-b\""));
        assertTrue(payload.contains("\"sid\":\"opaque-session-id-123\""));
        assertTrue(payload.contains("\"jti\":\"jti-abc-123\""));
        assertTrue(payload.contains("\"iat\":" + Instant.parse("2026-01-15T10:00:00Z").getEpochSecond()));
        assertTrue(payload.contains("http://schemas.openid.net/event/backchannel-logout"));

        // AC-04: MUST NOT incluir nonce
        assertFalse(payload.contains("nonce"));
    }
}
