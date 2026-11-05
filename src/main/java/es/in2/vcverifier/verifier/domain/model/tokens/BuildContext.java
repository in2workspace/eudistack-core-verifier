package es.in2.vcverifier.verifier.domain.model.tokens;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;

import java.time.Instant;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.AUTHENTICATION_RESULT;

public record BuildContext(
        JsonNode credential,
        String credentialConfigurationId,
        ExtractedClaims extractedClaims,
        Instant issueTime,
        Instant expirationTime,
        String audience,
        String tenant,
        Map<String, Object> additionalParameters,
        boolean generateIdToken
) {

    public AuthenticationResult authentication() {
        return additionalParameters != null
                && additionalParameters.get(AUTHENTICATION_RESULT) instanceof AuthenticationResult authentication
                ? authentication
                : null;
    }
}
