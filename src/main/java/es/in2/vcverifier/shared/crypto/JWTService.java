package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;

public interface JWTService {

    String issueJWT(String payload);

    void verifyJWTWithECKey(String jwt, PublicKey publicKey);

    SignedJWT parseJWT(String jwt);

    Payload extractPayloadFromSignedJWT(SignedJWT signedJWT);

    String extractClaimFromPayload(Payload payload, String claimName);

    long extractExpirationFromPayload(Payload payload);

    Object extractVCFromPayload(Payload payload);

    String issueJWTwithOI4VPType(String s);

    /**
     * US-06 [W3]: emite un JWT firmado con un {@code typ} de cabecera JOSE explícito, distinto
     * del {@code JWT} estándar de {@link #issueJWT(String)}. Usado por el {@code logout_token}
     * ({@code typ=logout+jwt}, OIDC Back-Channel Logout 1.0 §2.4/§5) para prevenir confusión de
     * tipo de token, ya que la misma clave EC firma id_token/access_token/logout_token.
     */
    String issueJWTwithType(String payload, String type);
}
