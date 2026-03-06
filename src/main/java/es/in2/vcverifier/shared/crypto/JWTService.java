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
}
