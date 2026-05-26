package es.in2.vcverifier.verifier.dualformat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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

        ObjectNode legacyJson = MAPPER.createObjectNode();
        legacyClaims.getClaims().forEach((k, v) -> legacyJson.set(k, MAPPER.valueToTree(v)));

        ObjectNode bumpedJson = MAPPER.createObjectNode();
        bumpedClaims.getClaims().forEach((k, v) -> bumpedJson.set(k, MAPPER.valueToTree(v)));

        legacyJson.remove("jti");
        legacyJson.remove("iat");
        legacyJson.remove("exp");

        bumpedJson.remove("jti");
        bumpedJson.remove("iat");
        bumpedJson.remove("exp");

        String legacyStr = MAPPER.writeValueAsString(legacyJson);
        String bumpedStr = MAPPER.writeValueAsString(bumpedJson);

        JSONAssert.assertEquals(legacyStr, bumpedStr, JSONCompareMode.LENIENT);
    }
}
