package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.model.validation.RevocationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.ClaimMapping;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.TokenClaimsMapping;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationPaths;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class LocalSchemaProfileRegistry implements SchemaProfileRegistry {

    private static final String CLASSPATH_SCHEMA_BASE = "schemas/";
    private final Map<String, SchemaProfile> profiles = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public LocalSchemaProfileRegistry(String externalSchemasDir) {
        loadFromExternalDir(externalSchemasDir);
        loadFromClasspath();
        log.info("Schema Profile Registry loaded {} profiles: {}", profiles.size(), profiles.keySet());
    }

    @Override
    public Optional<SchemaProfile> findByConfigId(String credentialConfigurationId) {
        return Optional.ofNullable(profiles.get(credentialConfigurationId));
    }

    @Override
    public boolean hasProfile(String credentialConfigurationId) {
        return profiles.containsKey(credentialConfigurationId);
    }

    private void loadFromExternalDir(String externalSchemasDir) {
        if (externalSchemasDir == null || externalSchemasDir.isBlank()) return;
        Path dir = Path.of(externalSchemasDir);
        if (!Files.isDirectory(dir)) return;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.json")) {
            for (Path file : stream) {
                try (InputStream is = Files.newInputStream(file)) {
                    parseAndRegister(is, file.toString());
                }
            }
        } catch (IOException e) {
            log.error("Failed to scan external schemas directory: {}", externalSchemasDir, e);
        }
    }

    private void loadFromClasspath() {
        // Classpath schemas are embedded in the JAR; try known patterns
        // This is a fallback — external dir is the primary source in production
        String[] knownSchemas = {
                "learcredential.employee.w3c.1.json",
                "learcredential.employee.w3c.1.profile.json",
                "learcredential.employee.sd.1.json",
                "learcredential.employee.sd.1.profile.json",
                "learcredential.machine.w3c.1.json",
                "learcredential.machine.w3c.1.profile.json",
                "learcredential.machine.sd.1.json",
                "learcredential.machine.sd.1.profile.json",
                "gx.labelcredential.w3c.1.json",
                "gx.labelcredential.w3c.1.profile.json"
        };
        for (String schemaFile : knownSchemas) {
            String path = CLASSPATH_SCHEMA_BASE + schemaFile;
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(path)) {
                if (is != null) {
                    parseAndRegister(is, "classpath:" + path);
                }
            } catch (IOException e) {
                log.warn("Failed to load schema from classpath: {}", path, e);
            }
        }
    }

    private void parseAndRegister(InputStream is, String source) {
        try {
            JsonNode root = objectMapper.readTree(is);
            JsonNode configIdNode = root.get("credential_configuration_id");
            if (configIdNode == null || !configIdNode.isTextual()) {
                log.debug("Skipping {} — no credential_configuration_id", source);
                return;
            }
            String configId = configIdNode.asText();
            if (profiles.containsKey(configId)) {
                log.debug("Profile {} already loaded, skipping {}", configId, source);
                return;
            }

            JsonNode mappingNode = root.get("token_claims_mapping");
            if (mappingNode == null || mappingNode.isMissingNode()) {
                log.debug("Skipping {} — no token_claims_mapping", source);
                return;
            }

            String topLevelScope = root.has("scope") ? root.get("scope").asText() : null;
            TokenClaimsMapping mapping = parseTokenClaimsMapping(mappingNode);

            ValidationPaths validationPaths = parseValidationPaths(root.get("validation"));
            Set<String> grantEligibility = parseStringSet(root.get("grant_eligibility"));
            boolean schemaRequired = parseSchemaRequired(root.get("validation"));
            String issuerIdPath = parseNullableText(root, "validation", "issuer_id_path");
            String mandatorOrgIdPath = parseNullableText(root, "validation", "mandator_org_id_path");

            SchemaProfile profile = new SchemaProfile(
                    configId,
                    topLevelScope,
                    mapping,
                    validationPaths,
                    grantEligibility,
                    schemaRequired,
                    issuerIdPath,
                    mandatorOrgIdPath
            );
            profiles.put(configId, profile);
            log.info("Registered schema profile: {} from {}", configId, source);
        } catch (Exception e) {
            log.error("Failed to parse schema profile from {}: {}", source, e.getMessage());
        }
    }

    private TokenClaimsMapping parseTokenClaimsMapping(JsonNode node) {
        List<String> subjectPaths = parseStringList(node.get("subject_paths"));
        Map<String, ClaimMapping> idTokenClaims = parseClaimMappings(node.get("id_token"));
        Map<String, ClaimMapping> accessTokenClaims = parseClaimMappings(node.get("access_token"));
        Map<String, String> idTokenEmbed = parseStringMap(node.get("id_token_embed"));
        Map<String, String> accessTokenEmbed = parseStringMap(node.get("access_token_embed"));
        String scope = node.has("scope") ? node.get("scope").asText() : null;

        return new TokenClaimsMapping(subjectPaths, idTokenClaims, accessTokenClaims, idTokenEmbed, accessTokenEmbed, scope);
    }

    private Map<String, ClaimMapping> parseClaimMappings(JsonNode node) {
        if (node == null || !node.isObject()) return Map.of();

        Map<String, ClaimMapping> mappings = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> {
            String claimName = entry.getKey();
            JsonNode value = entry.getValue();
            ClaimMapping mapping = parseClaimMapping(value);
            if (mapping != null) {
                mappings.put(claimName, mapping);
            }
        });
        return Collections.unmodifiableMap(mappings);
    }

    private ClaimMapping parseClaimMapping(JsonNode value) {
        // Shorthand: plain string = direct path
        if (value.isTextual()) {
            return new ClaimMapping.DirectPath(value.asText());
        }
        // Object form with strategy
        if (value.isObject()) {
            String strategy = value.has("strategy") ? value.get("strategy").asText() : "path";
            return switch (strategy) {
                case "concat" -> {
                    List<String> paths = parseStringList(value.get("paths"));
                    String separator = value.has("separator") ? value.get("separator").asText() : " ";
                    yield new ClaimMapping.Concat(paths, separator);
                }
                case "constant" -> {
                    JsonNode val = value.get("value");
                    Object javaValue = val.isBoolean() ? val.booleanValue()
                            : val.isNumber() ? val.numberValue()
                            : val.asText();
                    yield new ClaimMapping.Constant(javaValue);
                }
                default -> {
                    // "path" strategy in object form
                    String path = value.has("path") ? value.get("path").asText() : null;
                    yield path != null ? new ClaimMapping.DirectPath(path) : null;
                }
            };
        }
        return null;
    }

    private Map<String, String> parseStringMap(JsonNode node) {
        if (node == null || !node.isObject()) return Map.of();
        Map<String, String> map = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> map.put(entry.getKey(), entry.getValue().asText()));
        return Collections.unmodifiableMap(map);
    }

    private List<String> parseStringList(JsonNode node) {
        if (node == null || !node.isArray()) return List.of();
        List<String> list = new ArrayList<>();
        for (JsonNode item : node) {
            list.add(item.asText());
        }
        return Collections.unmodifiableList(list);
    }

    private Set<String> parseStringSet(JsonNode node) {
        if (node == null || !node.isArray()) return Set.of();
        Set<String> set = new LinkedHashSet<>();
        for (JsonNode item : node) {
            set.add(item.asText());
        }
        return Collections.unmodifiableSet(set);
    }

    private ValidationPaths parseValidationPaths(JsonNode node) {
        if (node == null || !node.isObject()) return null;
        String validFromPath = textOrNull(node, "valid_from_path");
        String validUntilPath = textOrNull(node, "valid_until_path");
        RevocationPaths revocation = parseRevocationPaths(node.get("revocation"));
        return new ValidationPaths(validFromPath, validUntilPath, revocation);
    }

    private RevocationPaths parseRevocationPaths(JsonNode node) {
        if (node == null || node.isNull() || !node.isObject()) return null;
        return new RevocationPaths(
                textOrNull(node, "status_id_path"),
                textOrNull(node, "status_type_path"),
                textOrNull(node, "status_purpose_path"),
                textOrNull(node, "status_list_credential_path"),
                textOrNull(node, "status_list_index_path")
        );
    }

    private boolean parseSchemaRequired(JsonNode validationNode) {
        if (validationNode == null || !validationNode.isObject()) return false;
        JsonNode schemaReq = validationNode.get("schema_required");
        return schemaReq != null && schemaReq.asBoolean(false);
    }

    private String parseNullableText(JsonNode root, String parentField, String childField) {
        JsonNode parent = root.get(parentField);
        if (parent == null || !parent.isObject()) return null;
        return textOrNull(parent, childField);
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) return null;
        return value.asText();
    }
}
