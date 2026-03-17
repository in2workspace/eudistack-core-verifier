package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.shared.crypto.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

/**
 * Application workflow that generates access tokens and ID tokens from a validated credential.
 * Extracts the credential type, delegates to the appropriate ClaimsExtractor SPI,
 * resolves the subject DID, and builds the JWT tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationWorkflow {

    private final JWTService jwtService;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final List<ClaimsExtractor> claimsExtractors;

    public record Result(
            String accessTokenJwt,
            Instant issueTime,
            Instant expirationTime,
            String idTokenJwt,
            String scope,
            String subject
    ) {}

    /**
     * Generates an access token (and optionally an ID token) from a validated credential.
     *
     * @param credentialJson       the credential as a JsonNode
     * @param audience             the audience for the tokens
     * @param additionalParameters map containing optional SCOPE, NONCE, etc.
     * @param generateIdToken      true to generate an ID token (for authorization_code and refresh_token grants)
     * @param tenant               the tenant identifier from the OIDC client registration
     * @return a Result with the JWT strings and metadata
     */
    public Result issueAccessToken(JsonNode credentialJson, String audience, Map<String, Object> additionalParameters, boolean generateIdToken, String tenant) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                backendConfig.getAccessTokenExpirationSeconds(),
                ChronoUnit.SECONDS
        );

        String credentialType = extractCredentialType(credentialJson);
        ExtractedClaims extractedClaims = extractClaims(credentialType, credentialJson);
        String subject = extractedClaims.subject();

        String accessTokenJwt = buildAccessToken(credentialJson, extractedClaims, issueTime, expirationTime, subject, audience, tenant);

        String idTokenJwt = null;
        if (generateIdToken) {
            idTokenJwt = buildIdToken(credentialJson, extractedClaims, subject, audience, additionalParameters);
        }

        return new Result(accessTokenJwt, issueTime, expirationTime, idTokenJwt, extractedClaims.scope(), subject);
    }

    public String extractCredentialType(JsonNode credentialJson) {
        // W3C VCDM: type array
        JsonNode typeNode = credentialJson.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim — returns the config ID directly
        JsonNode vctNode = credentialJson.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            return vctNode.asText();
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "Cannot determine credential type from 'type' or 'vct' field",
                null));
    }



    private ExtractedClaims extractClaims(String credentialType, JsonNode credentialJson) {
        for (ClaimsExtractor extractor : claimsExtractors) {
            if (extractor.supports(credentialType)) {
                return extractor.extract(credentialJson);
            }
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "No claims extractor found for credential type: " + credentialType,
                null));
    }

    private String buildAccessToken(JsonNode credentialJson, ExtractedClaims extractedClaims,
                                     Instant issueTime, Instant expirationTime,
                                     String subject, String audience, String tenant) {
        log.info("Generating access token for credential_type: {}, tenant: {}", extractCredentialType(credentialJson), tenant);

        JWTClaimsSet.Builder payloadBuilder = new JWTClaimsSet.Builder()
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, extractedClaims.scope())
                .claim("credential_type", extractCredentialType(credentialJson));

        if (extractedClaims.accessTokenClaims() != null) {
            extractedClaims.accessTokenClaims().forEach(payloadBuilder::claim);
        }

        if (extractedClaims.accessTokenEmbeds() != null) {
            extractedClaims.accessTokenEmbeds().forEach(payloadBuilder::claim);
        }

        // Tenant from client registration takes precedence over any credential-extracted tenant
        if (tenant != null && !tenant.isBlank()) {
            payloadBuilder.claim("tenant", tenant);
        }

        JWTClaimsSet payload = payloadBuilder.build();
        return jwtService.issueJWT(payload.toString());
    }

    private String buildIdToken(JsonNode credentialJson, ExtractedClaims extractedClaims,
                                 String subject, String audience, Map<String, Object> additionalParameters) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                backendConfig.getIdTokenExpirationSeconds(),
                ChronoUnit.SECONDS
        );

        String verifiableCredentialJson;
        try {
            verifiableCredentialJson = objectMapper.writeValueAsString(credentialJson);
        } catch (Exception e) {
            throw new JsonConversionException("Error converting Verifiable Credential to JSON: " + e.getMessage());
        }

        JWTClaimsSet.Builder idTokenClaimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("auth_time", Date.from(issueTime))
                .claim("acr", "0")
                .claim("credential_type", extractCredentialType(credentialJson))
                .claim("vc_json", verifiableCredentialJson);

        if (additionalParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            extractedClaims.idTokenClaims().forEach(idTokenClaimsBuilder::claim);
        }

        if (extractedClaims.idTokenEmbeds() != null) {
            extractedClaims.idTokenEmbeds().forEach(idTokenClaimsBuilder::claim);
        }

        if (additionalParameters.containsKey(NONCE)) {
            idTokenClaimsBuilder.claim(NONCE, additionalParameters.get(NONCE));
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();
        return jwtService.issueJWT(idTokenClaims.toString());
    }
}
