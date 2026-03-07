package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
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
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
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
    private final CredentialMapperService credentialMapperService;
    private final CryptographicBindingValidator cryptographicBindingValidator;

    @Override
    public void verifyVerifiablePresentation(String verifiablePresentation) {
        log.info("Starting validation of Verifiable Presentation");

        // Step 1: Extract the first VC from the VP
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);

        Payload payload = jwtService.extractPayloadFromSignedJWT(jwtCredential);

        // Step 2: Map to typed credential
        LEARCredential learCredential = credentialMapperService.mapPayloadToVerifiableCredential(payload);

        // Step 3: Validate time window
        validateCredentialTimeWindow(learCredential);

        // Step 4: Validate revocation (only if credentialStatus is present)
        // Non-blocking: if the status list endpoint is unreachable or returns an error,
        // log a warning and let the presentation pass. Only block if revocation is confirmed.
        if (hasCredentialStatus(learCredential)) {
            log.debug("CredentialStatus detected: {}", learCredential.credentialStatusId());
            try {
                if (!validateCredentialNotRevoked(learCredential)) {
                    throw new CredentialRevokedException("Credential ID " + learCredential.id() + " is revoked.");
                }
                log.info("Credential is not revoked");
            } catch (CredentialRevokedException e) {
                throw e;
            } catch (Exception e) {
                log.warn("Could not verify credential revocation status for credential {}. " +
                        "Status list may be unreachable. Proceeding with presentation. Error: {}",
                        learCredential.id(), e.getMessage());
            }
        } else {
            log.debug("No CredentialStatus block found; skipping revocation check for credential {}", learCredential.id());
        }

        // Step 5: Extract issuer identifier from JWT iss claim
        String credentialIssuer = extractIssFromJwt(jwtCredential);

        // Step 6: Validate credential types against issuer capabilities
        List<String> credentialTypes = learCredential.type();
        List<IssuerCredentialsCapabilities> issuerCapabilitiesList = trustFrameworkService.getTrustedIssuerListData(credentialIssuer);
        validateCredentialTypeWithIssuerCapabilities(issuerCapabilitiesList, credentialTypes);
        log.info("Issuer {} is a trusted participant", credentialIssuer);

        // Step 7: Verify VC signature and certificate
        String issuerOrgId = learCredential.issuer().getOrganizationIdentifier();
        if (issuerOrgId == null || issuerOrgId.isBlank()) {
            issuerOrgId = credentialIssuer;
        }
        Map<String, Object> vcHeader = jwtCredential.getHeader().toJSONObject();
        certificateValidationService.extractAndVerifyCertificate(jwtCredential.serialize(), vcHeader, issuerOrgId);

        // Step 8: Validate mandator organization
        String mandatorOrganizationIdentifier = learCredential.mandatorOrganizationIdentifier();
        trustFrameworkService.getTrustedIssuerListData(mandatorOrganizationIdentifier);
        log.info("Mandator OrganizationIdentifier {} is valid and allowed", mandatorOrganizationIdentifier);

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

    private void validateCredentialTimeWindow(LEARCredential credential) {
        try {
            ZonedDateTime validFrom = ZonedDateTime.parse(credential.validFrom());
            ZonedDateTime validUntil = ZonedDateTime.parse(credential.validUntil());
            ZonedDateTime now = ZonedDateTime.now();

            if (now.isBefore(validFrom)) {
                throw new CredentialNotActiveException("Credential is not yet valid. Valid from: " + validFrom);
            }
            if (now.isAfter(validUntil)) {
                throw new CredentialExpiredException("Credential has expired. Valid until: " + validUntil);
            }
        } catch (DateTimeParseException e) {
            throw new CredentialMappingException("Invalid date format in credential: " + e.getMessage());
        }
    }

    private boolean hasCredentialStatus(LEARCredential credential) {
        if (!credential.learCredentialStatusExist()) {
            return false;
        }
        return credential.credentialStatusId() != null && !credential.credentialStatusId().isBlank() &&
                credential.credentialStatusType() != null && !credential.credentialStatusType().isBlank() &&
                credential.credentialStatusPurpose() != null && !credential.credentialStatusPurpose().isBlank();
    }

    private boolean validateCredentialNotRevoked(LEARCredential learCredential) {
        if (!REVOCATION.equals(learCredential.credentialStatusPurpose())) {
            log.error("credentialStatus is not revocation: {}", learCredential.credentialStatusPurpose());
            return false;
        }

        String type = learCredential.credentialStatusType();

        if ("BitstringStatusListEntry".equals(type)) {
            log.info("Validating credential with BitstringStatusListEntry credential status");
            return !trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                    learCredential.statusListCredential(),
                    learCredential.credentialStatusListIndex(),
                    learCredential.credentialStatusPurpose()
            );
        }

        throw new CredentialException("Unsupported credentialStatus.type: " + type);
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
