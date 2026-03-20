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
import es.in2.vcverifier.verifier.domain.util.CredentialTypeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class GenericCredentialFactory {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final SchemaProfileRegistry schemaProfileRegistry;

    public GenericCredential create(Payload payload) {
        Object vcObject = jwtService.extractVCFromPayload(payload);
        JsonNode root = toJsonNode(vcObject);

        String configId = CredentialTypeResolver.resolveConfigId(root);
        List<String> types = extractTypes(root);
        List<String> context = extractContext(root);

        SchemaProfile profile = schemaProfileRegistry.findByConfigId(configId)
                .orElseThrow(() -> new InvalidCredentialTypeException(
                        "No schema profile found for credential type: " + configId));

        return new GenericCredential(root, profile, configId, types, context);
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
