package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.AccessTokenBuilder;
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
    private final AccessTokenBuilder accessTokenBuilder;

    // US-06 (AD-6 / ADR-109): estampado condicional del claim `sid` en el id_token —
    // cross-BC de lectura oauth2 → sso, ver spec-deltas.md DELTA-03.
    private final SsoSessionRepositoryPort ssoSessionRepositoryPort;
    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final HashingService hashingService;

    public record Result(
            String accessTokenJwt,
            Instant issueTime,
            Instant expirationTime,
            String idTokenJwt,
            Map<String, Object> idTokenClaims,
            String scope,
            String subject
    ) {}

    private record IdTokenBuildResult(String jwt, Map<String, Object> claims) {}

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

        String credentialConfigurationId = extractCredentialType(credentialJson);
        ExtractedClaims extractedClaims = extractClaims(credentialConfigurationId, credentialJson);
        String subject = extractedClaims.subject();

        BuildContext buildContext = new BuildContext(
            credentialJson,
            credentialConfigurationId,
            extractedClaims,
            issueTime,
            expirationTime,
            audience,
            tenant,
            additionalParameters,
            generateIdToken
        );

        String accessTokenJwt = accessTokenBuilder.build(buildContext);

        String idTokenJwt = null;
        Map<String, Object> idTokenClaims = null;
        if (generateIdToken) {
            IdTokenBuildResult idTokenResult = buildIdToken(credentialJson, extractedClaims, subject, audience, additionalParameters, tenant);
            idTokenJwt = idTokenResult.jwt();
            idTokenClaims = idTokenResult.claims();
        }

        return new Result(accessTokenJwt, issueTime, expirationTime, idTokenJwt, idTokenClaims, extractedClaims.scope(), subject);
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

    private IdTokenBuildResult buildIdToken(JsonNode credentialJson, ExtractedClaims extractedClaims,
                                 String subject, String audience, Map<String, Object> additionalParameters,
                                 String tenant) {
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

        stampSidIfActiveSsoSession(idTokenClaimsBuilder, tenant, subject);

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();
        String jwt = jwtService.issueJWT(idTokenClaims.toString());
        return new IdTokenBuildResult(jwt, idTokenClaims.toJSONObject());
    }

    /**
     * US-06 (AD-6 / ADR-109): estampa {@code sid} = {@code sso_session.id} (valor en crudo,
     * sin derivar) cuando el tenant tiene SSO habilitado y existe una sesión {@code ACTIVE}
     * para {@code (tenant, sha256(subject))}. Sin sesión o SSO deshabilitado, el {@code id_token}
     * no lleva {@code sid} — comportamiento idéntico al previo a esta Story (AC-05).
     * <p>
     * Best-effort / fail-open: cualquier fallo en la resolución (BBDD, config) se registra y
     * se omite el claim — el estampado de {@code sid} nunca debe impedir la emisión del
     * {@code id_token}, que es camino crítico de autenticación.
     */
    private void stampSidIfActiveSsoSession(JWTClaimsSet.Builder idTokenClaimsBuilder, String tenant, String subject) {
        if (tenant == null) {
            return;
        }
        try {
            tenantSsoConfigPort.getByTenant(tenant)
                    .filter(TenantSsoConfig::ssoEnabled)
                    .ifPresent(config -> {
                        String holderHash = hashingService.sha256(subject);
                        ssoSessionRepositoryPort.findActiveByTenantAndHolder(tenant, holderHash)
                                .ifPresent(session -> idTokenClaimsBuilder.claim("sid", session.getId().getValue()));
                    });
        } catch (Exception e) {
            log.warn("sso_sid_stamp_lookup_failed tenant={}", tenant, e);
        }
    }
}
