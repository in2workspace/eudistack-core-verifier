package es.in2.vcverifier.verifier.dualformat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessTokenStructureParityIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void accessTokenRootClaimsAreIndistinguishableIgnoringJtiAndTimestamps() throws Exception {
        var legacy = support.readFixture("fixtures/dome/employee-3.json");
        var bumped = support.readFixture("fixtures/dome/employee-4.json");

        var legacyResult = support.runFlow(legacy);
        var bumpedResult = support.runFlow(bumped);

        JWTClaimsSet legacyClaims = legacyResult.claimsSet();
        JWTClaimsSet bumpedClaims = bumpedResult.claimsSet();

        assertNotNull(legacyClaims.getClaim("credential_type"));
        assertNotNull(bumpedClaims.getClaim("credential_type"));

        Map<String, Object> legacyEnvelope = normalizedEnvelope(legacyClaims);
        Map<String, Object> bumpedEnvelope = normalizedEnvelope(bumpedClaims);

        assertEquals(legacyEnvelope.keySet(), bumpedEnvelope.keySet());
        assertEquals(legacyEnvelope, bumpedEnvelope);

        assertEquals("LEARCredentialEmployee.3", legacyClaims.getStringClaim("credential_type"));
        assertEquals("LEARCredentialEmployee.4", bumpedClaims.getStringClaim("credential_type"));
        assertTrue(legacyClaims.getClaim("vc") instanceof Map);
        assertTrue(bumpedClaims.getClaim("vc") instanceof Map);
    }

    private Map<String, Object> normalizedEnvelope(JWTClaimsSet claimsSet) {
        Map<String, Object> normalized = new LinkedHashMap<>(claimsSet.getClaims());
        normalized.remove("jti");
        normalized.remove("iat");
        normalized.remove("exp");
        normalized.put("credential_type", "<credential_type>");
        normalized.put("vc", "<vc>");
        return normalized;
    }
}
