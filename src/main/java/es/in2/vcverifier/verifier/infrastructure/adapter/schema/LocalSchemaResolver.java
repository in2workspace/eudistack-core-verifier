package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SpecVersion;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaResolver;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves JSON Schemas from local resources using the naming pattern:
 * {@code {CredentialType}.{credential_format}.{version}.json}
 * where {@code credential_format} uses underscores instead of + or -
 * (e.g. {@code jwt_vc_json}, {@code dc_sd_jwt}).
 * <p>
 * Resolution priority: external directory (if configured) → classpath fallback.
 * SD-JWT credentials are identified by the presence of a {@code vct} claim.
 */
@Slf4j
public class LocalSchemaResolver implements CredentialSchemaResolver {

    private static final String CLASSPATH_SCHEMA_BASE = "schemas/";
    private static final String FORMAT_JWT_VC_JSON             = "jwt_vc_json";
    private static final String FORMAT_DC_SD_JWT               = "dc_sd_jwt";
    private static final String TYPE_LEAR_CREDENTIAL_EMPLOYEE  = "LEARCredentialEmployee";
    private static final String TYPE_LEAR_CREDENTIAL_MACHINE   = "LEARCredentialMachine";

    private final Map<String, JsonSchema> cache = new ConcurrentHashMap<>();
    private final String externalSchemasDir;

    public LocalSchemaResolver() {
        this(null);
    }

    public LocalSchemaResolver(String externalSchemasDir) {
        this.externalSchemasDir = externalSchemasDir;
    }

    private record CredentialTypeVersion(String type, String format, String version) {}

    // Context URL → (credentialType, format, version) for W3C VC credentials
    private static final Map<String, CredentialTypeVersion> CONTEXT_MAP = Map.of(
            "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1",
            new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_EMPLOYEE, FORMAT_JWT_VC_JSON, "v1"),

            "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2",
            new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_EMPLOYEE, FORMAT_JWT_VC_JSON, "v2"),

            "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3",
            new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_EMPLOYEE, FORMAT_JWT_VC_JSON, "v3"),

            "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2",
            new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_MACHINE, FORMAT_JWT_VC_JSON, "v2")
    );

    // VCT URI → (credentialType, format, version) for SD-JWT VC credentials
    private static final Map<String, CredentialTypeVersion> VCT_MAP = Map.of(
            "eu.europa.ec.eudi.lce.1", new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_EMPLOYEE, FORMAT_DC_SD_JWT, "v3"),
            "eu.europa.ec.eudi.lcm.1", new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_MACHINE,  FORMAT_DC_SD_JWT, "v2")
    );

    // Default for LEARCredentialMachine without any recognised context (legacy)
    private static final CredentialTypeVersion MACHINE_V1_DEFAULT =
            new CredentialTypeVersion(TYPE_LEAR_CREDENTIAL_MACHINE, FORMAT_JWT_VC_JSON, "v1");

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Optional<JsonSchema> resolve(String credentialType, List<String> context, JsonNode credential) {
        CredentialTypeVersion tv = resolveTypeVersion(credentialType, context, credential);
        if (tv == null) {
            log.debug("No local schema mapping found for type={}, context={}", credentialType, context);
            return Optional.empty();
        }

        String schemaFileName = tv.type() + "." + tv.format() + "." + tv.version() + ".json";
        return Optional.ofNullable(cache.computeIfAbsent(schemaFileName, this::loadSchema));
    }

    public static String resolveVersion(String credentialType, List<String> context) {
        CredentialTypeVersion tv = resolveTypeVersion(credentialType, context, null);
        return tv != null ? tv.version() : null;
    }

    public static String resolveTypeName(String credentialType, List<String> context) {
        CredentialTypeVersion tv = resolveTypeVersion(credentialType, context, null);
        return tv != null ? tv.type() : credentialType;
    }

    private static CredentialTypeVersion resolveTypeVersion(String credentialType, List<String> context, JsonNode credential) {
        // SD-JWT: detected by presence of 'vct' claim (no @context in SD-JWT payloads)
        if (credential != null && credential.has("vct")) {
            CredentialTypeVersion tv = VCT_MAP.get(credential.get("vct").asText());
            if (tv != null) return tv;
        }

        // W3C VC: resolve from @context URLs
        if (context != null) {
            for (String ctx : context) {
                CredentialTypeVersion tv = CONTEXT_MAP.get(ctx);
                if (tv != null) return tv;
            }
        }

        // Default: LEARCredentialMachine V1 (legacy credentials without recognised context)
        if (TYPE_LEAR_CREDENTIAL_MACHINE.equals(credentialType)) {
            return MACHINE_V1_DEFAULT;
        }

        return null;
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
