package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JsonSchemaCredentialValidatorTest {

    @TempDir
    Path tempDir;

    private JsonSchemaCredentialValidator validator;

    @BeforeEach
    void setUp() throws IOException {
        // Write a minimal employee W3C schema that requires credentialSubject.mandate.mandatee
        String employeeSchema = """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "type": "object",
                  "required": ["@context", "type", "issuer", "credentialSubject"],
                  "additionalProperties": true,
                  "properties": {
                    "@context": { "type": "array" },
                    "type": { "type": "array" },
                    "issuer": { "type": "object" },
                    "credentialSubject": {
                      "type": "object",
                      "required": ["mandate"],
                      "properties": {
                        "mandate": {
                          "type": "object",
                          "required": ["mandatee", "mandator", "power"],
                          "properties": {
                            "mandatee": { "type": "object" },
                            "mandator": { "type": "object" },
                            "power": { "type": "array" }
                          }
                        }
                      }
                    }
                  }
                }
                """;
        Files.writeString(tempDir.resolve("learcredential.employee.w3c.4.json"), employeeSchema);

        String machineSchema = employeeSchema
                .replace("employee.w3c.4", "machine.w3c.3");
        Files.writeString(tempDir.resolve("learcredential.machine.w3c.3.json"), machineSchema);

        LocalSchemaResolver resolver = new LocalSchemaResolver(tempDir.toString());
        validator = new JsonSchemaCredentialValidator(List.of(resolver));
    }

    @Test
    void validate_validEmployeeCredential_success() {
        JsonNode credential = buildEmployeeW3c4();

        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid());
        assertEquals("learcredential.employee.w3c.4", result.credentialType());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void validate_validMachineCredential_success() {
        JsonNode credential = buildMachineW3c3();

        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid());
        assertEquals("learcredential.machine.w3c.3", result.credentialType());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void validate_employeeMissingMandatee_fails() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.4");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");
        ObjectNode cs = vc.putObject("credentialSubject");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");
        // mandatee intentionally omitted

        ValidationResult result = validator.validate(vc);

        assertFalse(result.valid());
        assertFalse(result.errors().isEmpty());
    }

    @Test
    void validate_unknownCredentialType_passesWithoutSchema() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("SomeNewCredentialType");

        ValidationResult result = validator.validate(vc);

        assertTrue(result.valid());
        assertEquals("SomeNewCredentialType", result.credentialType());
    }

    // --- Helper methods ---

    private JsonNode buildEmployeeW3c4() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context")
                .add("https://www.w3.org/ns/credentials/v2")
                .add("https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3");

        vc.putArray("type").add("VerifiableCredential").add("learcredential.employee.w3c.4");
        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678").put("organizationIdentifier", "VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "urn:uuid:test");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("email", "test@example.com").put("firstName", "John").put("lastName", "Doe");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildMachineW3c3() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        vc.putArray("type").add("VerifiableCredential").add("learcredential.machine.w3c.3");
        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678").put("organizationIdentifier", "VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "urn:uuid:test-machine");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("domain", "api.example.com").put("ipAddress", "10.0.0.1");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }
}
