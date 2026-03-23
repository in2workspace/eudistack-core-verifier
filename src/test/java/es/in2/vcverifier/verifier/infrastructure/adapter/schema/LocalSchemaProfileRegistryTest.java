package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import es.in2.vcverifier.verifier.domain.model.validation.RevocationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LocalSchemaProfileRegistryTest {

    @TempDir
    Path tempDir;

    @Test
    void parseAndRegister_withValidationAndGrantEligibility_parsesAllFields() throws IOException {
        // Given
        String json = """
                {
                  "credential_configuration_id": "test.w3c.1",
                  "scope": "openid test",
                  "validation": {
                    "schema_required": true,
                    "valid_from_path": "validFrom",
                    "valid_until_path": "validUntil",
                    "issuer_id_path": "issuer.organizationIdentifier",
                    "mandator_org_id_path": "credentialSubject.mandate.mandator.organizationIdentifier",
                    "revocation": {
                      "status_id_path": "credentialStatus.id",
                      "status_type_path": "credentialStatus.type",
                      "status_purpose_path": "credentialStatus.statusPurpose",
                      "status_list_credential_path": "credentialStatus.statusListCredential",
                      "status_list_index_path": "credentialStatus.statusListIndex"
                    }
                  },
                  "grant_eligibility": ["client_credentials", "authorization_code"],
                  "token_claims_mapping": {
                    "subject_paths": ["credentialSubject.email"],
                    "id_token": {},
                    "access_token": {}
                  }
                }
                """;
        Files.writeString(tempDir.resolve("test.w3c.1.profile.json"), json);

        // When
        var registry = new LocalSchemaProfileRegistry(tempDir.toString());

        // Then
        assertTrue(registry.hasProfile("test.w3c.1"));
        SchemaProfile profile = registry.findByConfigId("test.w3c.1").orElseThrow();

        assertTrue(profile.schemaRequired());
        assertEquals("issuer.organizationIdentifier", profile.issuerIdPath());
        assertEquals("credentialSubject.mandate.mandator.organizationIdentifier", profile.mandatorOrgIdPath());
        assertEquals(Set.of("client_credentials", "authorization_code"), profile.grantEligibility());

        ValidationPaths vp = profile.validationPaths();
        assertNotNull(vp);
        assertEquals("validFrom", vp.validFromPath());
        assertEquals("validUntil", vp.validUntilPath());

        RevocationPaths rp = vp.revocation();
        assertNotNull(rp);
        assertEquals("credentialStatus.id", rp.statusIdPath());
        assertEquals("credentialStatus.type", rp.statusTypePath());
        assertEquals("credentialStatus.statusPurpose", rp.statusPurposePath());
        assertEquals("credentialStatus.statusListCredential", rp.statusListCredentialPath());
        assertEquals("credentialStatus.statusListIndex", rp.statusListIndexPath());
    }

    @Test
    void parseAndRegister_withoutValidationSection_usesDefaults() throws IOException {
        // Given
        String json = """
                {
                  "credential_configuration_id": "legacy.w3c.1",
                  "scope": "openid legacy",
                  "token_claims_mapping": {
                    "subject_paths": ["credentialSubject.email"],
                    "id_token": {},
                    "access_token": {}
                  }
                }
                """;
        Files.writeString(tempDir.resolve("legacy.w3c.1.profile.json"), json);

        // When
        var registry = new LocalSchemaProfileRegistry(tempDir.toString());

        // Then
        assertTrue(registry.hasProfile("legacy.w3c.1"));
        SchemaProfile profile = registry.findByConfigId("legacy.w3c.1").orElseThrow();

        assertNull(profile.validationPaths());
        assertEquals(Set.of(), profile.grantEligibility());
        assertFalse(profile.schemaRequired());
        assertNull(profile.issuerIdPath());
        assertNull(profile.mandatorOrgIdPath());
    }

    @Test
    void parseAndRegister_withNullRevocation_parsesValidationWithoutRevocation() throws IOException {
        // Given
        String json = """
                {
                  "credential_configuration_id": "norevoc.w3c.1",
                  "scope": "openid norevoc",
                  "validation": {
                    "schema_required": false,
                    "valid_from_path": "validFrom",
                    "valid_until_path": "validUntil",
                    "issuer_id_path": null,
                    "mandator_org_id_path": null,
                    "revocation": null
                  },
                  "grant_eligibility": ["authorization_code"],
                  "token_claims_mapping": {
                    "subject_paths": ["credentialSubject.id"],
                    "access_token": {}
                  }
                }
                """;
        Files.writeString(tempDir.resolve("norevoc.w3c.1.profile.json"), json);

        // When
        var registry = new LocalSchemaProfileRegistry(tempDir.toString());

        // Then
        SchemaProfile profile = registry.findByConfigId("norevoc.w3c.1").orElseThrow();

        assertFalse(profile.schemaRequired());
        assertNull(profile.issuerIdPath());
        assertNull(profile.mandatorOrgIdPath());

        ValidationPaths vp = profile.validationPaths();
        assertNotNull(vp);
        assertEquals("validFrom", vp.validFromPath());
        assertEquals("validUntil", vp.validUntilPath());
        assertNull(vp.revocation());
    }

    @Test
    void parseAndRegister_grantEligibility_parsedAsSet() throws IOException {
        // Given
        String json = """
                {
                  "credential_configuration_id": "grants.sd.1",
                  "scope": "openid grants",
                  "grant_eligibility": ["client_credentials", "authorization_code", "client_credentials"],
                  "token_claims_mapping": {
                    "subject_paths": ["email"],
                    "id_token": {},
                    "access_token": {}
                  }
                }
                """;
        Files.writeString(tempDir.resolve("grants.sd.1.profile.json"), json);

        // When
        var registry = new LocalSchemaProfileRegistry(tempDir.toString());

        // Then
        SchemaProfile profile = registry.findByConfigId("grants.sd.1").orElseThrow();
        // Duplicates are removed because it is a Set
        assertEquals(Set.of("client_credentials", "authorization_code"), profile.grantEligibility());
    }
}
