package es.in2.vcverifier.verifier.infrastructure.adapter.claims;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Extracts claims from LEAR Credentials (Employee and Machine, all versions)
 * using JSON path navigation with coalesce for field name differences across versions.
 * <p>
 * Supports all credential_configuration_ids that follow the LEAR credential structure
 * (mandate with mandatee, mandator, and power arrays).
 */
@Slf4j
public class LearCredentialClaimsExtractor implements ClaimsExtractor {

    private static final Set<String> EMPLOYEE_CONFIG_IDS = Set.of(
            "learcredential.employee.w3c.4",
            "learcredential.employee.sd.1"
    );

    private static final Set<String> MACHINE_CONFIG_IDS = Set.of(
            "learcredential.machine.w3c.3",
            "learcredential.machine.sd.1"
    );

    @Override
    public boolean supports(String credentialType) {
        return EMPLOYEE_CONFIG_IDS.contains(credentialType)
                || MACHINE_CONFIG_IDS.contains(credentialType);
    }

    @Override
    public ExtractedClaims extract(JsonNode credential) {
        JsonNode mandatee = credential.at("/credentialSubject/mandate/mandatee");
        JsonNode mandator = credential.at("/credentialSubject/mandate/mandator");

        String subjectDid = resolveSubjectDid(credential, mandatee);
        String mandatorOrgId = coalesce(
                mandator.path("organizationIdentifier").asText(null)
        );
        String issuerDid = resolveIssuerDid(credential);

        // Determine credential type for scope
        String credentialType = extractCredentialType(credential);
        boolean isEmployee = EMPLOYEE_CONFIG_IDS.contains(credentialType);

        String scope = isEmployee ? "openid learcredential" : "machine learcredential";

        // ID Token claims (OpenID Connect standard claims for employees)
        Map<String, Object> idTokenClaims = new HashMap<>();
        if (isEmployee) {
            String firstName = coalesce(
                    mandatee.path("firstName").asText(null),
                    mandatee.path("first_name").asText(null)
            );
            String lastName = coalesce(
                    mandatee.path("lastName").asText(null),
                    mandatee.path("last_name").asText(null)
            );
            String email = mandatee.path("email").asText(null);

            if (firstName != null && lastName != null) {
                idTokenClaims.put("name", firstName + " " + lastName);
                idTokenClaims.put("given_name", firstName);
                idTokenClaims.put("family_name", lastName);
            }
            if (email != null) {
                idTokenClaims.put("email", email);
                idTokenClaims.put("email_verified", true);
            }
        }

        // Access token claims (tenant derived from mandator organizationIdentifier)
        Map<String, Object> accessTokenClaims = new HashMap<>();
        if (mandatorOrgId != null) {
            accessTokenClaims.put("tenant", mandatorOrgId);
        }

        return ExtractedClaims.builder()
                .subjectDid(subjectDid)
                .mandatorOrgId(mandatorOrgId)
                .issuerDid(issuerDid)
                .idTokenClaims(idTokenClaims)
                .accessTokenClaims(accessTokenClaims)
                .scope(scope)
                .build();
    }

    private String resolveSubjectDid(JsonNode credential, JsonNode mandatee) {
        // Priority 1: credentialSubject.id
        String csId = credential.at("/credentialSubject/id").asText(null);
        if (csId != null && !csId.isBlank()) {
            return csId;
        }

        // Priority 2: mandatee.id
        String mandateeId = mandatee.path("id").asText(null);
        if (mandateeId != null && !mandateeId.isBlank()) {
            return mandateeId;
        }

        log.warn("Cannot resolve subject DID from credential JSON paths");
        return null;
    }

    private String resolveIssuerDid(JsonNode credential) {
        // W3C VCDM: issuer as string or object with organizationIdentifier
        JsonNode issuerNode = credential.path("issuer");
        if (issuerNode.isTextual()) {
            return issuerNode.asText();
        }
        if (issuerNode.isObject()) {
            String orgId = issuerNode.path("organizationIdentifier").asText(null);
            if (orgId != null) return orgId;
            return issuerNode.path("id").asText(null);
        }
        // SD-JWT VC: iss claim at top level
        JsonNode issNode = credential.path("iss");
        if (issNode.isTextual()) {
            return issNode.asText();
        }
        return null;
    }

    private String extractCredentialType(JsonNode credential) {
        // W3C VCDM: type array — returns the config ID directly
        JsonNode typeNode = credential.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim — returns the config ID directly
        JsonNode vctNode = credential.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            return vctNode.asText();
        }
        return "Unknown";
    }

    @SafeVarargs
    private static <T> T coalesce(T... values) {
        for (T val : values) {
            if (val != null) {
                return val;
            }
        }
        return null;
    }
}
