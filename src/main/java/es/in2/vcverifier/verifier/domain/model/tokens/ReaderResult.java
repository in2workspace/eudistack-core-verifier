package es.in2.vcverifier.verifier.domain.model.tokens;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;

public record ReaderResult(
        JsonNode credential,
        String credentialConfigurationId,
        SchemaProfile schemaProfile,
        boolean wrapVcInAccessToken
) {
}
