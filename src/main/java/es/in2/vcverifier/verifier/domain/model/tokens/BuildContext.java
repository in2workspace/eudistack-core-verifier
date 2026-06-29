package es.in2.vcverifier.verifier.domain.model.tokens;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;

import java.time.Instant;
import java.util.Map;

public record BuildContext(
        JsonNode credential,
        DispatchDecision dispatchDecision,
        ExtractedClaims extractedClaims,
        Instant issueTime,
        Instant expirationTime,
        String audience,
        String tenant,
        Map<String, Object> additionalParameters,
        boolean generateIdToken
) {
}
