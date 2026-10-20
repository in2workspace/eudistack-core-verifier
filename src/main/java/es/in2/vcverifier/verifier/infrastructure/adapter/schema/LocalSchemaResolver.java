package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SpecVersion;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaResolver;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Resolves JSON Schemas from local resources.
 * <p>
 * Since credential types now use the credential_configuration_id as their type/vct value
 * (e.g., "learcredential.employee.w3c.4"), the schema file name is simply {@code {configId}.json}.
 * <p>
 * Resolution priority: external directory (if configured) → legacy subdirectory → classpath fallback.
 */
@Slf4j
public class LocalSchemaResolver implements CredentialSchemaResolver {

    private static final String CLASSPATH_SCHEMA_BASE = "schemas/";

    private final Map<String, JsonSchema> cache = new ConcurrentHashMap<>();
    private final String externalSchemasDir;
    private final SchemaProfileRegistry schemaProfileRegistry;

    public LocalSchemaResolver() {
        this(null);
    }

    public LocalSchemaResolver(String externalSchemasDir) {
        this(externalSchemasDir, null);
    }

    public LocalSchemaResolver(String externalSchemasDir, SchemaProfileRegistry schemaProfileRegistry) {
        this.externalSchemasDir = externalSchemasDir;
        this.schemaProfileRegistry = schemaProfileRegistry;
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Optional<JsonSchema> resolve(String credentialType, List<String> context, JsonNode credential) {
        // For W3C the type IS the config ID; for SD-JWT the vct may be an alias of it
        // (e.g. urn:es.cgcom:doctorid:1 → doctorid.sd.1), which the profile registry maps back
        String configId = credentialType;
        if (credential != null && credential.has("vct")) {
            configId = toConfigId(credential.get("vct").asText());
        }

        String schemaFileName = configId + ".json";
        log.debug("Resolving schema for configId={}, file={}", configId, schemaFileName);

        return Optional.ofNullable(cache.computeIfAbsent(schemaFileName, this::loadSchema));
    }

    private String toConfigId(String vct) {
        if (schemaProfileRegistry == null) {
            return vct;
        }
        return schemaProfileRegistry.findByConfigId(vct)
                .map(SchemaProfile::credentialConfigurationId)
                .orElse(vct);
    }

    public static String resolveVersion(String credentialType, List<String> context) {
        // No longer needed — the config ID encodes the version
        return null;
    }

    public static String resolveTypeName(String credentialType, List<String> context) {
        // The credential type IS the config ID — return as-is
        return credentialType;
    }

    private JsonSchema loadSchema(String schemaFileName) {
        if (externalSchemasDir != null && !externalSchemasDir.isBlank()) {
            // 1. Current schemas (root)
            JsonSchema schema = tryLoadFromFile(Path.of(externalSchemasDir, schemaFileName));
            if (schema != null) return schema;

            // 2. Legacy schemas (verifier-only, old credential versions)
            schema = tryLoadFromFile(Path.of(externalSchemasDir, "legacy", schemaFileName));
            if (schema != null) return schema;
        }

        // 3. Classpath fallback (production without volume mount)
        return loadFromClasspath(schemaFileName);
    }

    private JsonSchema tryLoadFromFile(Path file) {
        if (!Files.exists(file)) return null;
        try (InputStream is = new FileInputStream(file.toFile())) {
            JsonSchema schema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
                    .getSchema(is, new com.networknt.schema.SchemaValidatorsConfig.Builder().build());
            log.info("Loaded JSON Schema from external file: {}", file);
            return schema;
        } catch (Exception e) {
            log.error("Failed to load JSON Schema from {}: {}", file, e.getMessage());
            return null;
        }
    }

    private JsonSchema loadFromClasspath(String schemaFileName) {
        String classpathPath = CLASSPATH_SCHEMA_BASE + schemaFileName;
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(classpathPath)) {
            if (is == null) {
                log.warn("Schema not found on classpath: {}", classpathPath);
                return null;
            }
            JsonSchema schema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
                    .getSchema(SchemaLocation.of("classpath:" + classpathPath),
                            new com.networknt.schema.SchemaValidatorsConfig.Builder().build());
            log.info("Loaded JSON Schema from classpath: {}", classpathPath);
            return schema;
        } catch (Exception e) {
            log.error("Failed to load JSON Schema from {}: {}", classpathPath, e.getMessage());
            return null;
        }
    }
}
