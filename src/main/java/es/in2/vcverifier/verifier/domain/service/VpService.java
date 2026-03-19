package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

public interface VpService {
    void verifyVerifiablePresentation(String verifiablePresentation);
    Object extractCredentialFromVerifiablePresentation(String verifiablePresentation);
    JsonNode extractCredentialFromVerifiablePresentationAsJsonNode(String verifiablePresentation);
    List<String> extractContextFromJson(JsonNode verifiableCredential);
}
