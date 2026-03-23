package es.in2.vcverifier.verifier.domain.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CredentialTypeResolverTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void resolveConfigId_w3cTypeArray_returnsFirstNonGenericType() {
        // Given
        ObjectNode credential = mapper.createObjectNode();
        ArrayNode types = mapper.createArrayNode();
        types.add("VerifiableCredential");
        types.add("VerifiableAttestation");
        types.add("LEARCredentialEmployee");
        credential.set("type", types);

        // When
        String result = CredentialTypeResolver.resolveConfigId(credential);

        // Then
        assertEquals("LEARCredentialEmployee", result);
    }

    @Test
    void resolveConfigId_sdJwtVctClaim_returnsVctValue() {
        // Given
        ObjectNode credential = mapper.createObjectNode();
        credential.put("vct", "learcredential.employee.sd.1");

        // When
        String result = CredentialTypeResolver.resolveConfigId(credential);

        // Then
        assertEquals("learcredential.employee.sd.1", result);
    }

    @Test
    void resolveConfigId_onlyGenericTypesWithVct_fallsBackToVct() {
        // Given
        ObjectNode credential = mapper.createObjectNode();
        ArrayNode types = mapper.createArrayNode();
        types.add("VerifiableCredential");
        types.add("VerifiableAttestation");
        credential.set("type", types);
        credential.put("vct", "learcredential.machine.sd.1");

        // When
        String result = CredentialTypeResolver.resolveConfigId(credential);

        // Then
        assertEquals("learcredential.machine.sd.1", result);
    }

    @Test
    void resolveConfigId_noTypeOrVct_throwsInvalidCredentialTypeException() {
        // Given
        ObjectNode credential = mapper.createObjectNode();
        credential.put("id", "some-credential-id");

        // When & Then
        InvalidCredentialTypeException exception = assertThrows(
                InvalidCredentialTypeException.class,
                () -> CredentialTypeResolver.resolveConfigId(credential));
        assertEquals("Cannot resolve credential type: no 'type' array or 'vct' claim found",
                exception.getMessage());
    }
}
