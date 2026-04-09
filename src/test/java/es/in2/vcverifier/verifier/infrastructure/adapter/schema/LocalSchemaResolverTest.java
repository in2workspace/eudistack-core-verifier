package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LocalSchemaResolverTest {

    @TempDir
    Path tempDir;

    private LocalSchemaResolver resolver;

    @BeforeEach
    void setUp() throws IOException {
        // Create minimal valid JSON Schema files in the temp directory
        String minimalSchema = """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "type": "object",
                  "additionalProperties": true
                }
                """;
        Files.writeString(tempDir.resolve("learcredential.employee.w3c.4.json"), minimalSchema);
        Files.writeString(tempDir.resolve("learcredential.machine.w3c.3.json"),
                minimalSchema.replace("employee.w3c.4", "machine.w3c.3"));

        // Create a legacy subdirectory with legacy schemas
        Path legacyDir = tempDir.resolve("legacy");
        Files.createDirectories(legacyDir);
        Files.writeString(legacyDir.resolve("learcredential.employee.w3c.2.json"),
                minimalSchema.replace("employee.w3c.4", "employee.w3c.2"));

        resolver = new LocalSchemaResolver(tempDir.toString());
    }

    @Test
    void order_returns20() {
        assertEquals(20, resolver.order());
    }

    @Test
    void resolve_employeeW3c4_returnsSchema() {
        Optional<JsonSchema> schema = resolver.resolve(
                "learcredential.employee.w3c.4",
                List.of("https://www.w3.org/ns/credentials/v2"),
                JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_machineW3c3_returnsSchema() {
        Optional<JsonSchema> schema = resolver.resolve(
                "learcredential.machine.w3c.3",
                List.of("https://www.w3.org/ns/credentials/v2"),
                JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_legacyEmployee_returnsSchemaFromLegacyDir() {
        Optional<JsonSchema> schema = resolver.resolve(
                "learcredential.employee.w3c.2",
                List.of("https://www.w3.org/ns/credentials/v2"),
                JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_unknownType_returnsEmpty() {
        Optional<JsonSchema> schema = resolver.resolve(
                "SomeOtherCredential",
                List.of("https://www.w3.org/ns/credentials/v2"),
                JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isEmpty());
    }

    @Test
    void resolve_cachedSchema_returnsSameInstance() {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");

        Optional<JsonSchema> first = resolver.resolve("learcredential.employee.w3c.4", context, node);
        Optional<JsonSchema> second = resolver.resolve("learcredential.employee.w3c.4", context, node);

        assertTrue(first.isPresent());
        assertTrue(second.isPresent());
        assertSame(first.get(), second.get());
    }

    @Test
    void resolveVersion_alwaysReturnsNull() {
        String version = LocalSchemaResolver.resolveVersion(
                "learcredential.employee.w3c.4",
                List.of("https://www.w3.org/ns/credentials/v2"));
        assertNull(version);
    }

    @Test
    void resolveTypeName_returnsInput() {
        String type = LocalSchemaResolver.resolveTypeName(
                "learcredential.employee.w3c.4",
                List.of("https://www.w3.org/ns/credentials/v2"));
        assertEquals("learcredential.employee.w3c.4", type);
    }
}
