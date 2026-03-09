package es.in2.vcverifier.verifier.infrastructure.adapter.claims;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.ClaimMapping;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.TokenClaimsMapping;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class SchemaProfileClaimsExtractor implements ClaimsExtractor {

    private final SchemaProfileRegistry registry;

    @Override
    public boolean supports(String credentialType) {
        return registry.hasProfile(credentialType);
    }

    @Override
    public ExtractedClaims extract(JsonNode credential) {
        String configId = extractConfigId(credential);
        SchemaProfile profile = registry.findByConfigId(configId)
                .orElseThrow(() -> new IllegalStateException("No schema profile for: " + configId));

        TokenClaimsMapping mapping = profile.tokenClaimsMapping();

        String subject = resolveSubject(credential, mapping.subjectPaths());
        Map<String, Object> idTokenClaims = resolveClaims(credential, mapping.idTokenClaims());
        Map<String, Object> accessTokenClaims = resolveClaims(credential, mapping.accessTokenClaims());
        String scope = mapping.effectiveScope(profile.scope());

        return ExtractedClaims.builder()
                .subject(subject)
                .idTokenClaims(idTokenClaims)
                .accessTokenClaims(accessTokenClaims)
                .scope(scope)
                .build();
    }

    private String extractConfigId(JsonNode credential) {
        // W3C VCDM: type array
        JsonNode typeNode = credential.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim
        JsonNode vctNode = credential.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            return vctNode.asText();
        }
        return "Unknown";
    }

    private String resolveSubject(JsonNode credential, List<String> subjectPaths) {
        for (String path : subjectPaths) {
            String value = resolveTextPath(credential, path);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        log.warn("Cannot resolve subject from paths: {}", subjectPaths);
        return null;
    }

    private Map<String, Object> resolveClaims(JsonNode credential, Map<String, ClaimMapping> mappings) {
        if (mappings == null || mappings.isEmpty()) return Map.of();

        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, ClaimMapping> entry : mappings.entrySet()) {
            Object value = resolveClaimMapping(credential, entry.getValue());
            if (value != null) {
                result.put(entry.getKey(), value);
            }
        }
        return result;
    }

    private Object resolveClaimMapping(JsonNode credential, ClaimMapping mapping) {
        return switch (mapping) {
            case ClaimMapping.DirectPath dp -> resolveTextPath(credential, dp.path());
            case ClaimMapping.Concat concat -> {
                List<String> parts = concat.paths().stream()
                        .map(p -> resolveTextPath(credential, p))
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList());
                yield parts.isEmpty() ? null : String.join(concat.separator(), parts);
            }
            case ClaimMapping.Constant constant -> constant.value();
        };
    }

    private String resolveTextPath(JsonNode credential, String dotPath) {
        String jsonPointer = "/" + dotPath.replace(".", "/");
        JsonNode node = credential.at(jsonPointer);
        if (node.isMissingNode() || node.isNull()) return null;
        if (node.isTextual()) return node.asText();
        // For non-textual nodes (e.g. "issuer" as object), return null
        return null;
    }
}
