package es.in2.vcverifier.verifier.infrastructure.adapter.claims;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.ClaimMapping;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile.TokenClaimsMapping;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SchemaProfileClaimsExtractorTest {

    private SchemaProfileClaimsExtractor buildExtractor(SchemaProfile... profiles) {
        Map<String, SchemaProfile> map = new java.util.HashMap<>();
        for (SchemaProfile p : profiles) {
            map.put(p.credentialConfigurationId(), p);
        }
        SchemaProfileRegistry registry = new SchemaProfileRegistry() {
            @Override
            public Optional<SchemaProfile> findByConfigId(String id) {
                return Optional.ofNullable(map.get(id));
            }
            @Override
            public boolean hasProfile(String id) {
                return map.containsKey(id);
            }
        };
        return new SchemaProfileClaimsExtractor(registry);
    }

    private SchemaProfile employeeW3cProfile() {
        return new SchemaProfile(
                "learcredential.employee.w3c.1",
                "lear_credential_employee",
                new TokenClaimsMapping(
                        List.of("credentialSubject.id", "credentialSubject.mandate.mandatee.id"),
                        Map.of(
                                "given_name", new ClaimMapping.DirectPath("credentialSubject.mandate.mandatee.firstName"),
                                "family_name", new ClaimMapping.DirectPath("credentialSubject.mandate.mandatee.lastName"),
                                "email", new ClaimMapping.DirectPath("credentialSubject.mandate.mandatee.email"),
                                "name", new ClaimMapping.Concat(
                                        List.of("credentialSubject.mandate.mandatee.firstName", "credentialSubject.mandate.mandatee.lastName"),
                                        " "
                                ),
                                "email_verified", new ClaimMapping.Constant(true)
                        ),
                        Map.of("tenant", new ClaimMapping.DirectPath("credentialSubject.mandate.mandator.organizationIdentifier")),
                        "openid learcredential"
                )
        );
    }

    private SchemaProfile machineW3cProfile() {
        return new SchemaProfile(
                "learcredential.machine.w3c.1",
                "lear_credential_machine",
                new TokenClaimsMapping(
                        List.of("credentialSubject.id", "credentialSubject.mandate.mandatee.id"),
                        Map.of(),
                        Map.of("tenant", new ClaimMapping.DirectPath("credentialSubject.mandate.mandator.organizationIdentifier")),
                        "machine learcredential"
                )
        );
    }

    @Test
    void supports_knownType_true() {
        var extractor = buildExtractor(employeeW3cProfile());
        assertTrue(extractor.supports("learcredential.employee.w3c.1"));
    }

    @Test
    void supports_unknownType_false() {
        var extractor = buildExtractor(employeeW3cProfile());
        assertFalse(extractor.supports("some.unknown.type"));
    }

    @Test
    void extract_employee_allClaims() {
        var extractor = buildExtractor(employeeW3cProfile());
        JsonNode vc = buildEmployeeCredential("sub-123", "John", "Doe", "john@example.com");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("sub-123", claims.subject());
        assertEquals("openid learcredential", claims.scope());
        assertEquals("VATES-12345678", claims.accessTokenClaims().get("tenant"));
        assertEquals("John", claims.idTokenClaims().get("given_name"));
        assertEquals("Doe", claims.idTokenClaims().get("family_name"));
        assertEquals("john@example.com", claims.idTokenClaims().get("email"));
        assertEquals("John Doe", claims.idTokenClaims().get("name"));
        assertEquals(true, claims.idTokenClaims().get("email_verified"));
    }

    @Test
    void extract_machine_noIdTokenClaims() {
        var extractor = buildExtractor(machineW3cProfile());
        JsonNode vc = buildMachineCredential("machine-sub");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("machine-sub", claims.subject());
        assertEquals("machine learcredential", claims.scope());
        assertEquals("VATES-12345678", claims.accessTokenClaims().get("tenant"));
        assertTrue(claims.idTokenClaims().isEmpty());
    }

    @Test
    void extract_subjectFallsBackToMandateeId() {
        var extractor = buildExtractor(employeeW3cProfile());

        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.1");
        // No credentialSubject.id
        ObjectNode cs = vc.putObject("credentialSubject");
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", "fallback-sub");
        mandatee.put("firstName", "Test");
        mandatee.put("lastName", "User");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");

        ExtractedClaims claims = extractor.extract(vc);
        assertEquals("fallback-sub", claims.subject());
    }

    @Test
    void extract_concatSkipsNullParts() {
        var extractor = buildExtractor(employeeW3cProfile());

        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.1");
        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "sub-1");
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("firstName", "OnlyFirst");
        // no lastName
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");

        ExtractedClaims claims = extractor.extract(vc);
        assertEquals("OnlyFirst", claims.idTokenClaims().get("name"));
    }

    @Test
    void extract_missingClaimPath_omitsFromResult() {
        var extractor = buildExtractor(employeeW3cProfile());

        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.1");
        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "sub-1");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee");
        // no email, no names
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");

        ExtractedClaims claims = extractor.extract(vc);
        assertFalse(claims.idTokenClaims().containsKey("email"));
        assertFalse(claims.idTokenClaims().containsKey("given_name"));
        // constant is always present
        assertEquals(true, claims.idTokenClaims().get("email_verified"));
    }

    // --- Helpers ---

    private JsonNode buildEmployeeCredential(String subjectId, String firstName, String lastName, String email) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.1");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", subjectId);
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("firstName", firstName);
        mandatee.put("lastName", lastName);
        mandatee.put("email", email);
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");

        return vc;
    }

    private JsonNode buildMachineCredential(String subjectId) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.machine.w3c.1");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", subjectId);
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");

        return vc;
    }
}
