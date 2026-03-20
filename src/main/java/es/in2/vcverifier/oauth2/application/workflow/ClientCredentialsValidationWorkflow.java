package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import es.in2.vcverifier.verifier.domain.util.CredentialTypeResolver;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Application workflow that validates a client_credentials grant (M2M flow).
 * Parses the client_assertion JWT, extracts and validates the embedded VP token,
 * ensures the credential is a machine credential, and validates the assertion claims.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ClientCredentialsValidationWorkflow {

    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final SchemaProfileRegistry schemaProfileRegistry;

    /**
     * Validates an M2M client_credentials grant by:
     * 1. Parsing the client_assertion JWT and extracting the vp_token claim
     * 2. Extracting the credential from the VP
     * 3. Validating that the credential type is a machine credential
     * 4. Validating the client_assertion JWT claims
     * 5. Validating the VP (full pipeline)
     *
     * @param clientId        the client identifier
     * @param clientAssertion the client_assertion JWT containing the VP
     * @return the validated credential as a JsonNode
     */
    public JsonNode validateClientCredentialsGrant(String clientId, String clientAssertion) {
        log.info("ClientCredentialsValidationWorkflow: validating M2M grant");

        SignedJWT signedJWT = jwtService.parseJWT(clientAssertion);
        Payload payload = jwtService.extractPayloadFromSignedJWT(signedJWT);
        String vpToken = jwtService.extractClaimFromPayload(payload, "vp_token");
        String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);

        // Extract credential and validate grant eligibility via schema profile
        JsonNode vc = vpService.extractCredentialFromVerifiablePresentationAsJsonNode(decodedVpToken);
        String configId = CredentialTypeResolver.resolveConfigId(vc);
        SchemaProfile profile = schemaProfileRegistry.findByConfigId(configId)
                .orElseThrow(() -> new InvalidCredentialTypeException("No profile found for: " + configId));
        if (!profile.grantEligibility().contains("client_credentials")) {
            log.error("Credential type {} is not eligible for client_credentials grant", configId);
            throw new InvalidCredentialTypeException(
                    "Credential type " + configId + " is not eligible for client_credentials grant");
        }

        // Validate client assertion JWT claims
        boolean isValid = clientAssertionValidationService.verifyClientAssertionJWTClaims(clientId, payload);
        if (!isValid) {
            log.error("JWT claims from client_assertion are invalid");
            throw new IllegalArgumentException("Invalid JWT claims from assertion");
        }

        // Full VP validation
        vpService.verifyVerifiablePresentation(decodedVpToken);
        log.info("ClientCredentialsValidationWorkflow: VP validated successfully");

        return vc;
    }

}
