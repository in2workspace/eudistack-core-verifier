package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.verifier.domain.model.GenericCredential;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.model.validation.RevocationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;
import es.in2.vcverifier.verifier.domain.service.*;
import es.in2.vcverifier.shared.crypto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class VpServiceImpl implements VpService {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final TrustFrameworkService trustFrameworkService;
    private final CertificateValidationService certificateValidationService;
    private final GenericCredentialFactory genericCredentialFactory;
    private final CredentialValidator credentialValidator;
    private final CryptographicBindingValidator cryptographicBindingValidator;
    private final List<CredentialStatusVerifier> credentialStatusVerifiers;

    @Override
    public void verifyVerifiablePresentation(String verifiablePresentation) {
        log.info("Starting validation of Verifiable Presentation");

        // Step 1: Extract the first VC from the VP
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);

        Payload payload = jwtService.extractPayloadFromSignedJWT(jwtCredential);

        // Step 2: Map to generic credential using profile-based factory
        GenericCredential credential = genericCredentialFactory.create(payload);

        // Step 2b: Validate credential against JSON Schema
        ValidationResult schemaResult = credentialValidator.validate(credential.root());
        if (!schemaResult.valid()) {
            throw new CredentialSchemaValidationException(
                    "Credential schema validation failed for type '" + schemaResult.credentialType()
                            + "': " + String.join("; ", schemaResult.errors()));
        }
        log.info("Credential schema validation passed: type={}", schemaResult.credentialType());

        // Step 3: Validate time window
        validateCredentialTimeWindow(credential);

        // Step 4: Validate revocation (only if credentialStatus is present)
        // SEC-S2: Fail-closed — if revocation status cannot be determined, reject the credential.
        if (hasRevocationConfig(credential)) {
            log.debug("CredentialStatus detected in credential");
            if (!validateCredentialNotRevoked(credential)) {
                throw new CredentialRevokedException("Credential is revoked.");
            }
            log.info("Credential is not revoked");
        } else {
            log.debug("No CredentialStatus block found; skipping revocation check");
        }

        // Step 5: Extract issuer identifier from JWT iss claim
        String credentialIssuer = extractIssFromJwt(jwtCredential);

        // Step 6: Validate credential types against issuer capabilities
        List<String> credentialTypes = credential.types();
        List<IssuerCredentialsCapabilities> issuerCapabilitiesList = trustFrameworkService.getTrustedIssuerListData(credentialIssuer);
        validateCredentialTypeWithIssuerCapabilities(issuerCapabilitiesList, credentialTypes);
        log.info("Issuer {} is a trusted participant", credentialIssuer);

        // Step 7: Verify VC signature and certificate
        String issuerOrgId = credential.field(credential.profile().issuerIdPath()).orElse(null);
        if (issuerOrgId == null || issuerOrgId.isBlank()) {
            issuerOrgId = credentialIssuer;
        }
        Map<String, Object> vcHeader = jwtCredential.getHeader().toJSONObject();
        certificateValidationService.extractAndVerifyCertificate(jwtCredential.serialize(), vcHeader, issuerOrgId);

        // Step 8: Validate mandator organization (skip if no mandator path in profile)
        String mandatorOrgIdPath = credential.profile().mandatorOrgIdPath();
        if (mandatorOrgIdPath != null) {
            String mandatorOrgId = credential.field(mandatorOrgIdPath)
                    .orElseThrow(() -> new CredentialMappingException(
                            "Missing mandator org ID at path: " + mandatorOrgIdPath));
            trustFrameworkService.getTrustedIssuerListData(mandatorOrgId);
            log.info("Mandator OrganizationIdentifier {} is valid and allowed", mandatorOrgId);
        }

        // Step 9: Validate VP signature + cryptographic binding
        SignedJWT vpJwt = parseVpJwt(verifiablePresentation);
        cryptographicBindingValidator.validateVpSignatureAndBinding(
                verifiablePresentation, vpJwt, jwtCredential
        );

        log.info("Verifiable Presentation validation completed successfully");
    }

    @Override
    public Object extractCredentialFromVerifiablePresentation(String verifiablePresentation) {
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
        Payload payload = jwtService.extractPayloadFromSignedJWT(jwtCredential);
        return jwtService.extractVCFromPayload(payload);
    }

    @Override
    public JsonNode extractCredentialFromVerifiablePresentationAsJsonNode(String verifiablePresentation) {
        return convertObjectToJSONNode(extractCredentialFromVerifiablePresentation(verifiablePresentation));
    }

    @Override
    public List<String> extractContextFromJson(JsonNode verifiableCredential) {
        JsonNode contextNode = verifiableCredential.get("@context");
        if (contextNode == null || !contextNode.isArray()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "'@context' field is missing or is not an array",
                    null));
        }

        List<String> contextList = new ArrayList<>();
        for (JsonNode node : contextNode) {
            if (!node.isTextual()) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Elements of '@context' must be strings",
                        null));
            }
            contextList.add(node.asText());
        }
        return contextList;
    }

    // --- Private helpers ---

    private String extractIssFromJwt(SignedJWT jwtCredential) {
        try {
            String iss = jwtCredential.getJWTClaimsSet().getIssuer();
            if (iss == null || iss.isBlank()) {
                throw new JWTClaimMissingException("The 'iss' claim is missing from the VC JWT");
            }
            return iss;
        } catch (ParseException e) {
            throw new JWTParsingException("Error extracting 'iss' claim from VC JWT");
        }
    }

    private SignedJWT parseVpJwt(String verifiablePresentation) {
        try {
            return SignedJWT.parse(verifiablePresentation);
        } catch (Exception e) {
            throw new InvalidVPtokenException("Invalid vp_token JWT");
        }
    }

    private void validateCredentialTimeWindow(GenericCredential credential) {
        ValidationPaths vp = credential.profile().validationPaths();
        if (vp == null) {
            log.debug("No validation paths in profile; skipping time window check");
            return;
        }

        Instant validFrom = credential.timeField(vp.validFromPath())
                .orElseThrow(() -> new CredentialMappingException(
                        "Missing validFrom at path: " + vp.validFromPath()));
        Instant validUntil = credential.timeField(vp.validUntilPath())
                .orElseThrow(() -> new CredentialMappingException(
                        "Missing validUntil at path: " + vp.validUntilPath()));

        Instant now = Instant.now();
        if (now.isBefore(validFrom)) {
            throw new CredentialNotActiveException("Credential is not yet valid. Valid from: " + validFrom);
        }
        if (now.isAfter(validUntil)) {
            throw new CredentialExpiredException("Credential has expired. Valid until: " + validUntil);
        }
    }

    private boolean hasRevocationConfig(GenericCredential credential) {
        ValidationPaths vp = credential.profile().validationPaths();
        if (vp == null || vp.revocation() == null) {
            return false;
        }
        RevocationPaths rp = vp.revocation();
        return credential.field(rp.statusIdPath()).isPresent();
    }

    private boolean validateCredentialNotRevoked(GenericCredential credential) {
        RevocationPaths rp = credential.profile().validationPaths().revocation();

        String purpose = credential.field(rp.statusPurposePath()).orElse(null);
        if (purpose != null && !REVOCATION.equals(purpose)) {
            log.error("credentialStatus purpose is not 'revocation': {}", purpose);
            return false;
        }

        String type = credential.field(rp.statusTypePath()).orElse(null);
        String statusListCredential = credential.field(rp.statusListCredentialPath())
                .orElseThrow(() -> new CredentialException("Missing statusListCredential"));
        String statusListIndex = credential.field(rp.statusListIndexPath())
                .orElseThrow(() -> new CredentialException("Missing statusListIndex"));

        if (type == null) {
            for (CredentialStatusVerifier verifier : credentialStatusVerifiers) {
                try {
                    return !verifier.isRevoked(statusListCredential, statusListIndex, purpose);
                } catch (Exception e) {
                    log.debug("Verifier {} couldn't handle credential status: {}",
                            verifier.getClass().getSimpleName(), e.getMessage());
                }
            }
            throw new CredentialException(
                    "No credential status verifier could handle status at: " + statusListCredential);
        }

        CredentialStatusVerifier verifier = credentialStatusVerifiers.stream()
                .filter(v -> v.supports(type))
                .findFirst()
                .orElseThrow(() -> new CredentialException("Unsupported credentialStatus.type: " + type));

        log.info("Validating credential revocation with {} verifier", type);
        return !verifier.isRevoked(statusListCredential, statusListIndex, purpose);
    }

    private void validateCredentialTypeWithIssuerCapabilities(List<IssuerCredentialsCapabilities> issuerCapabilitiesList, List<String> credentialTypes) {
        for (String credentialType : credentialTypes) {
            boolean isSupported = issuerCapabilitiesList.stream().anyMatch(capability -> capability.credentialsType().equals(credentialType));
            if (isSupported) {
                return;
            }
        }
        throw new InvalidCredentialTypeException("Credential types " + credentialTypes + " are not supported by the issuer.");
    }

    private SignedJWT extractFirstVerifiableCredential(String verifiablePresentation) {
        try {
            SignedJWT vpSignedJWT = SignedJWT.parse(verifiablePresentation);
            Object vpClaim = vpSignedJWT.getJWTClaimsSet().getClaim("vp");
            Object vcClaim = getVcClaim(vpClaim);
            Object firstCredential = getFirstCredential(vcClaim);
            return SignedJWT.parse((String) firstCredential);
        } catch (ParseException e) {
            throw new JWTParsingException("Error parsing the Verifiable Presentation or Verifiable Credential");
        }
    }

    private static Object getVcClaim(Object vpClaim) {
        if (vpClaim == null) {
            throw new JWTClaimMissingException("The 'vp' claim was not found in the Verifiable Presentation");
        }
        if (!(vpClaim instanceof Map<?, ?> vpMap)) {
            throw new JWTClaimMissingException("The 'vp' claim is not a valid object");
        }
        Object vcClaim = vpMap.get("verifiableCredential");
        if (vcClaim == null) {
            throw new JWTClaimMissingException("The 'verifiableCredential' claim was not found within 'vp'");
        }
        return vcClaim;
    }

    private static Object getFirstCredential(Object vcClaim) {
        if (!(vcClaim instanceof List<?> verifiableCredentials)) {
            throw new CredentialException("The verifiableCredential claim is not an array");
        }
        if (verifiableCredentials.isEmpty()) {
            throw new CredentialException("No Verifiable Credential found in Verifiable Presentation");
        }
        Object firstCredential = verifiableCredentials.get(0);
        if (!(firstCredential instanceof String)) {
            throw new CredentialException("The first Verifiable Credential is not a valid JWT string");
        }
        return firstCredential;
    }

    private JsonNode convertObjectToJSONNode(Object vcObject) throws JsonConversionException {
        try {
            if (vcObject instanceof Map) {
                return objectMapper.convertValue(vcObject, JsonNode.class);
            } else if (vcObject instanceof JSONObject) {
                return objectMapper.readTree(vcObject.toString());
            } else {
                throw new JsonConversionException("Unsupported object type for JsonNode conversion.");
            }
        } catch (JsonConversionException e) {
            throw e;
        } catch (Exception e) {
            throw new JsonConversionException("Error during JsonNode conversion.");
        }
    }
}
