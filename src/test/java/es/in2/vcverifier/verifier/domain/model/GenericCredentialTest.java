package es.in2.vcverifier.verifier.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class GenericCredentialTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private GenericCredential buildCredential(String json) throws Exception {
        JsonNode root = OBJECT_MAPPER.readTree(json);
        SchemaProfile profile = mock(SchemaProfile.class);
        return new GenericCredential(root, profile, "test.w3c.1", List.of(), List.of());
    }

    @Test
    void field_withValidDotPath_returnsValue() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                {
                  "credentialSubject": {
                    "mandate": {
                      "mandator": {
                        "organizationIdentifier": "VATES-B12345678"
                      }
                    }
                  }
                }
                """);

        // When
        Optional<String> result = credential.field("credentialSubject.mandate.mandator.organizationIdentifier");

        // Then
        assertTrue(result.isPresent());
        assertEquals("VATES-B12345678", result.get());
    }

    @Test
    void field_withMissingPath_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                { "credentialSubject": {} }
                """);

        // When
        Optional<String> result = credential.field("credentialSubject.nonexistent.field");

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void field_withNullPath_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("{}");

        // When
        Optional<String> result = credential.field(null);

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void field_withNullValue_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                { "name": null }
                """);

        // When
        Optional<String> result = credential.field("name");

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void timeField_withIso8601String_parsesInstant() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                { "validFrom": "2025-01-15T10:00:00Z" }
                """);

        // When
        Optional<Instant> result = credential.timeField("validFrom");

        // Then
        assertTrue(result.isPresent());
        assertEquals(Instant.parse("2025-01-15T10:00:00Z"), result.get());
    }

    @Test
    void timeField_withEpochSeconds_parsesInstant() throws Exception {
        // Given
        long epoch = 1705312800L;
        GenericCredential credential = buildCredential("""
                { "exp": %d }
                """.formatted(epoch));

        // When
        Optional<Instant> result = credential.timeField("exp");

        // Then
        assertTrue(result.isPresent());
        assertEquals(Instant.ofEpochSecond(epoch), result.get());
    }

    @Test
    void timeField_withInvalidDate_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                { "validFrom": "not-a-date" }
                """);

        // When
        Optional<Instant> result = credential.timeField("validFrom");

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void timeField_withNullPath_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("{}");

        // When
        Optional<Instant> result = credential.timeField(null);

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void node_withValidPath_returnsSubtree() throws Exception {
        // Given
        GenericCredential credential = buildCredential("""
                {
                  "credentialSubject": {
                    "mandate": {
                      "power": [
                        { "id": "p1" },
                        { "id": "p2" }
                      ]
                    }
                  }
                }
                """);

        // When
        Optional<JsonNode> result = credential.node("credentialSubject.mandate.power");

        // Then
        assertTrue(result.isPresent());
        assertTrue(result.get().isArray());
        assertEquals(2, result.get().size());
    }

    @Test
    void node_withMissingPath_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("{}");

        // When
        Optional<JsonNode> result = credential.node("nonexistent.path");

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void node_withNullPath_returnsEmpty() throws Exception {
        // Given
        GenericCredential credential = buildCredential("{}");

        // When
        Optional<JsonNode> result = credential.node(null);

        // Then
        assertTrue(result.isEmpty());
    }
}
