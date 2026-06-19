package es.in2.vcverifier.verifier.dualformat;

import org.junit.jupiter.api.Test;

import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SchemaProfileGrantEligibilityBumpedIT {

    @Test
    void bumpedProfileIncludesClientCredentialsGrant() {
        SchemaProfile profile = new SchemaProfile("LEARCredentialMachine.3", "openid", null, null, Set.of("authorization_code", "client_credentials"), false, null, null, true);
        assertTrue(profile.grantEligibility().contains("client_credentials"));
    }
}
