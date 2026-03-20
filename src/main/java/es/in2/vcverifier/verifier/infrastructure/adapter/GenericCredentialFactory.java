package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.GenericCredential;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class GenericCredentialFactory {

    private static final Set<String> GENERIC_TYPES = Set.of("VerifiableCredential", "VerifiableAttestation");

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final SchemaProfileRegistry schemaProfileRegistry;

    public GenericCredential create(Payload payload) {
        Object vcObject = jwtService.extractVCFromPayload(payload);
        JsonNode root = toJsonNode(vcObject);

        String configId = resolveCredentialConfigurationId(root);
        List<String> types = extractTypes(root);
        List<String> context = extractContext(root);

        SchemaProfile profile = schemaProfileRegistry.findByConfigId(configId)
                .orElseThrow(() -> new InvalidCredentialTypeException(
                        "No schema profile found for credential type: " + configId));

        return new GenericCredential(root, profile, configId, types, context);
    }

    private String resolveCredentialConfigurationId(JsonNode root) {
        // W3C VCDM: type[] array — pick the first non-generic type
        JsonNode typeNode = root.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!GENERIC_TYPES.contains(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim
        JsonNode vctNode = root.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            return vctNode.asText();
        }
        throw new InvalidCredentialTypeException(
                "Cannot resolve credential type: no 'type' array or 'vct' claim found");
    }

    private List<String> extractTypes(JsonNode root) {
        JsonNode typeNode = root.get("type");
        if (typeNode == null || !typeNode.isArray()) {
            return List.of();
        }
        List<String> types = new ArrayList<>();
        for (JsonNode t : typeNode) {
            types.add(t.asText());
        }
        return List.copyOf(types);
    }

    private List<String> extractContext(JsonNode root) {
        JsonNode contextNode = root.get("@context");
        if (contextNode == null || !contextNode.isArray()) {
            return List.of();
        }
        List<String> context = new ArrayList<>();
        for (JsonNode c : contextNode) {
            if (c.isTextual()) {
                context.add(c.asText());
            }
        }
        return List.copyOf(context);
    }

    private JsonNode toJsonNode(Object vcObject) {
        if (vcObject instanceof Map) {
            return objectMapper.convertValue(vcObject, JsonNode.class);
        } else if (vcObject instanceof JSONObject) {
            try {
                return objectMapper.readTree(vcObject.toString());
            } catch (Exception e) {
                throw new JsonConversionException("Failed to convert JSONObject to JsonNode");
            }
        }
        throw new JsonConversionException(
                "Unsupported VC object type: " + vcObject.getClass().getName());
    }
}
