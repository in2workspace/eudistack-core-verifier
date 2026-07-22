package es.in2.vcverifier.sso.infrastructure.backchannel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.exception.JWTCreationException;
import es.in2.vcverifier.sso.domain.model.LogoutToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.LOGOUT_JWT_TYPE;

/**
 * US-06 (Single Logout): construye y firma el {@code logout_token} conforme a
 * OIDC Back-Channel Logout 1.0 §2.4. Reutiliza {@link JWTService#issueJWT(String)}
 * (mismo signer {@code alg=ES256} + {@code kid} publicado en {@code /oidc/jwks}, EC P-256 de
 * {@code CryptoComponent}) — no reimplementa la firma, mismo mecanismo que el resto de
 * tokens del Verifier (p. ej. el {@code id_token} en {@code TokenGenerationWorkflow}).
 */
@Component
@RequiredArgsConstructor
public class LogoutTokenFactory {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;

    public String build(LogoutToken token) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", token.iss());
        claims.put("aud", token.aud());
        claims.put("sid", token.sid());
        claims.put("iat", token.iat().getEpochSecond());
        claims.put("exp", token.exp().getEpochSecond());
        claims.put("jti", token.jti());
        claims.put("events", token.events());

        try {
            String payload = objectMapper.writeValueAsString(claims);
            return jwtService.issueJWTwithType(payload, LOGOUT_JWT_TYPE);
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Error creating logout_token: " + e.getMessage());
        }
    }
}
