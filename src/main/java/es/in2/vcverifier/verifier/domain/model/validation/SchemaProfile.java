package es.in2.vcverifier.verifier.domain.model.validation;

import java.util.List;
import java.util.Map;

public record SchemaProfile(
        String credentialConfigurationId,
        String scope,
        TokenClaimsMapping tokenClaimsMapping
) {
    public record TokenClaimsMapping(
            List<String> subjectPaths,
            Map<String, ClaimMapping> idTokenClaims,
            Map<String, ClaimMapping> accessTokenClaims,
            String scope
    ) {
        public String effectiveScope(String fallbackScope) {
            return scope != null ? scope : fallbackScope;
        }
    }

    public sealed interface ClaimMapping
            permits ClaimMapping.DirectPath, ClaimMapping.Concat, ClaimMapping.Constant {

        record DirectPath(String path) implements ClaimMapping {}
        record Concat(List<String> paths, String separator) implements ClaimMapping {}
        record Constant(Object value) implements ClaimMapping {}
    }
}
