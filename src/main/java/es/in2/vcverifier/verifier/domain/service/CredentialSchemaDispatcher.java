package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;

public interface CredentialSchemaDispatcher {
    DispatchDecision dispatch(JsonNode credential);
}
