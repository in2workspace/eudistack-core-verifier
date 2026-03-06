package es.in2.vcverifier.oauth2.domain.service;

import com.nimbusds.jose.Payload;

public interface ClientAssertionValidationService {
    boolean verifyClientAssertionJWTClaims(String clientId, Payload payload);
}
