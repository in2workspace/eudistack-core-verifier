package es.in2.vcverifier.verifier.dualformat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public final class DomeCredentialFixtureFactory {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final byte[] HMAC_SECRET = "dome-test-secret-dome-test-secret".getBytes(StandardCharsets.UTF_8);

    public String signedLegacyEmployeeCredential() throws JOSEException {
        return sign(buildCredential("LEARCredentialEmployee.3", false));
    }

    public String signedLegacyMachineCredential() throws JOSEException {
        return sign(buildCredential("LEARCredentialMachine.2", false));
    }

    public String signedLegacyLabelCredential() throws JOSEException {
        return sign(buildCredential("gx:LabelCredential.1", false));
    }

    public String signedBumpedEmployeeCredential() throws JOSEException {
        return sign(buildCredential("LEARCredentialEmployee.4", true));
    }

    public String signedBumpedMachineCredential() throws JOSEException {
        return sign(buildCredential("LEARCredentialMachine.3", true));
    }

    public String signedBumpedLabelCredential() throws JOSEException {
        return sign(buildCredential("gx:LabelCredential.2", true));
    }

    public JsonNode legacyEmployeeCredential() {
        return buildCredential("LEARCredentialEmployee.3", false);
    }

    public JsonNode bumpedEmployeeCredential() {
        return buildCredential("LEARCredentialEmployee.4", true);
    }

    private String sign(ObjectNode credential) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
        JWSObject jwsObject = new JWSObject(header, new Payload(credential.toString()));
        jwsObject.sign(new MACSigner(HMAC_SECRET));
        return jwsObject.serialize();
    }

    private ObjectNode buildCredential(String configId, boolean bumped) {
        ObjectNode credential = OBJECT_MAPPER.createObjectNode();
        ArrayNode context = credential.putArray("@context");
        context.add(bumped ? "https://www.w3.org/ns/credentials/v2" : "https://www.w3.org/2018/credentials/v1");
        context.add("https://dome.example/contexts/" + normalizeConfigId(configId));

        ArrayNode type = credential.putArray("type");
        type.add("VerifiableCredential");
        type.add(configId);

        credential.put("credential_configuration_id", configId);
        credential.put("id", "urn:uuid:" + normalizeConfigId(configId) + "-" + Instant.now().toEpochMilli());
        credential.put("issuer", "did:web:dome.example");
        credential.put("issuanceDate", Instant.now().toString());

        ObjectNode credentialSubject = credential.putObject("credentialSubject");
        credentialSubject.put("id", "did:key:z6Mk" + normalizeConfigId(configId));

        ObjectNode mandate = credentialSubject.putObject("mandate");
        ObjectNode mandator = mandate.putObject("mandator");
        mandator.put("organizationIdentifier", "VATES-B12345678");
        mandator.put("commonName", "DOME Example Org");

        ObjectNode mandatee = mandate.putObject("mandatee");
        if (configId.contains("Employee")) {
            mandatee.put("firstName", "John");
            mandatee.put("lastName", "Doe");
            mandatee.put("email", "john.doe@example.com");
            mandatee.put("employeeId", "EMP-001");
        } else if (configId.contains("Machine")) {
            mandatee.put("domain", "machine.example.com");
            mandatee.put("ipAddress", "10.0.0.10");
        } else {
            mandatee.put("labelId", "LBL-001");
            mandatee.put("name", "Label Example");
        }

        ArrayNode power = mandate.putArray("power");
        ObjectNode powerItem = power.addObject();
        powerItem.put("function", "Onboarding");
        powerItem.put("action", "Execute");

        credential.putObject("credentialStatus")
                .put("id", "https://status.example/status/1");

        credential.put("validFrom", Instant.now().minusSeconds(60).toString());
        credential.put("validUntil", Instant.now().plusSeconds(3600).toString());
        return credential;
    }

    private String normalizeConfigId(String configId) {
        return configId.toLowerCase().replace('.', '-').replace(':', '-');
    }
}
