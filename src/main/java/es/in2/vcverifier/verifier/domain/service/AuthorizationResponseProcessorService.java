package es.in2.vcverifier.verifier.domain.service;

public interface AuthorizationResponseProcessorService {
    void handleAuthResponse(String state, String vpToken);
}
