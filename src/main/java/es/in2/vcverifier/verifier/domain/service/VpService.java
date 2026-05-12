package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

public interface VpService {
    void verifyVerifiablePresentation(String verifiablePresentation);
    void verifyVerifiablePresentation(String verifiablePresentation, boolean requireCnfBinding);
    Object extractCredentialFromVerifiablePresentation(String verifiablePresentation);
    JsonNode extractCredentialFromVerifiablePresentationAsJsonNode(String verifiablePresentation);
    public List<String> extractContextFromJson(JsonNode verifiableCredential);
}
