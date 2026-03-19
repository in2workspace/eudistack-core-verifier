package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalSchemaResolverTest {

    private LocalSchemaResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new LocalSchemaResolver();
    }

    @Test
    void order_returns20() {
        assertEquals(20, resolver.order());
    }

    @Test
    void resolve_employeeV1Context_returnsSchema() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee.jwt_vc_json.v1", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_employeeV2Context_returnsSchema() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee.jwt_vc_json.v2", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_employeeV3Context_returnsSchema() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee.jwt_vc_json.v3", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_machineWithoutSpecificContext_defaultsToV1() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialMachine.jwt_vc_json.v1", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_machineV2Context_returnsSchema() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialMachine.jwt_vc_json.v2", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_unknownType_returnsEmpty() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("SomeOtherCredential", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isEmpty());
    }

    @Test
    void resolve_cachedSchema_returnsSameInstance() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        Optional<JsonSchema> first = resolver.resolve("LEARCredentialEmployee.jwt_vc_json.v1", context, node);
        Optional<JsonSchema> second = resolver.resolve("LEARCredentialEmployee.jwt_vc_json.v1", context, node);

        assertTrue(first.isPresent());
        assertTrue(second.isPresent());
        assertSame(first.get(), second.get());
    }

    @Test
    void resolveVersion_alwaysReturnsNull() {
        String version = LocalSchemaResolver.resolveVersion("LEARCredentialEmployee.jwt_vc_json.v1", List.of(
                "https://www.w3.org/ns/credentials/v2"
        ));
        assertNull(version);
    }

    @Test
    void resolveVersion_machineDefault_returnsNull() {
        String version = LocalSchemaResolver.resolveVersion("LEARCredentialMachine.jwt_vc_json.v1", List.of("https://www.w3.org/ns/credentials/v2"));
        assertNull(version);
    }

    @Test
    void resolveVersion_unknownType_returnsNull() {
        String version = LocalSchemaResolver.resolveVersion("UnknownType", List.of("https://www.w3.org/ns/credentials/v2"));
        assertNull(version);
    }

    @Test
    void resolveTypeName_employeeV1() {
        String type = LocalSchemaResolver.resolveTypeName("LEARCredentialEmployee.jwt_vc_json.v1", List.of(
                "https://www.w3.org/ns/credentials/v2"
        ));
        assertEquals("LEARCredentialEmployee.jwt_vc_json.v1", type);
    }

    @Test
    void resolveTypeName_unknownType_returnsSameInput() {
        String type = LocalSchemaResolver.resolveTypeName("UnknownType", List.of("https://www.w3.org/ns/credentials/v2"));
        assertEquals("UnknownType", type);
    }
}
