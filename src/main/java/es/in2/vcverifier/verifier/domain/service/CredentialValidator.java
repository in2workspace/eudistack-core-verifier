package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;

import java.util.Set;

/**
 * Validates a credential's structure against its JSON Schema.
 */
public interface CredentialValidator {

    default ValidationResult validate(JsonNode credential) {
        return validate(credential, Set.of());
    }

    /**
     * @param requestedClaims top-level claims the verifier asked for. A selectively disclosed
     *                        presentation only carries those, so a mandatory claim outside this set
     *                        is not reported as missing. An empty set enforces every mandatory claim.
     */
    ValidationResult validate(JsonNode credential, Set<String> requestedClaims);
}
