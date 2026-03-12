package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.CertificateValidationService;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.model.StatusListCredentialData;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import es.in2.vcverifier.verifier.domain.service.StatusListCredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListVerifier implements CredentialStatusVerifier {

    private static final String SUPPORTED_TYPE = "BitstringStatusListEntry";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final CertificateValidationService certificateValidationService;
    private final StatusListCredentialService statusListCredentialService;
    private final HttpClient httpClient;
    private final SafeUrlValidator safeUrlValidator;

    @Override
    public boolean supports(String credentialStatusType) {
        return SUPPORTED_TYPE.equals(credentialStatusType);
    }

    @Override
    public boolean isRevoked(String statusListUrl, String statusIndex, String expectedPurpose) {
        log.info("Checking credential revocation in bitstring status list - URL: {}, Index: {}, Purpose: {}",
                statusListUrl, statusIndex, expectedPurpose);

        final int index = parseAndValidateIndex(statusIndex);

        final String jwtString = fetchStatusListCredentialJwt(statusListUrl);
        log.debug("Status List Credential JWT fetched successfully");

        final SignedJWT signedJwt = parseSignedJwt(jwtString);
        validateStatusListCredentialCertificate(jwtString, signedJwt);

        final StatusListCredentialData statusData = statusListCredentialService.parse(signedJwt);
        log.debug("Status List Credential parsed successfully. Purpose: {}", statusData.statusPurpose());

        statusListCredentialService.validateStatusPurposeMatches(
                statusData.statusPurpose(),
                expectedPurpose
        );

        final int maxBits = statusListCredentialService.maxBits(statusData.rawBitstringBytes());
        if (index >= maxBits) {
            throw new CredentialException(
                    "statusListIndex out of range. maxBits=" + maxBits + ", index=" + index
            );
        }

        final boolean isRevoked = statusListCredentialService.isBitSet(statusData.rawBitstringBytes(), index);

        log.info("Credential revocation check completed. Index: {}, IsRevoked: {}", index, isRevoked);

        return isRevoked;
    }

    private int parseAndValidateIndex(String statusListIndex) {
        final int index;
        try {
            index = Integer.parseInt(statusListIndex);
        } catch (NumberFormatException e) {
            throw new CredentialException(
                    "statusListIndex " + statusListIndex + " is not a valid integer: " + e.getMessage()
            );
        }
        if (index < 0) {
            throw new CredentialException("statusListIndex must be >= 0, but was: " + statusListIndex);
        }
        return index;
    }

    private String fetchStatusListCredentialJwt(String statusListCredentialUrl) {
        // SEC-14: SSRF protection — validate URL before outbound request
        safeUrlValidator.validate(statusListCredentialUrl);
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusListCredentialUrl))
                .header("Accept", "application/vc+jwt")
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException(
                    "Interrupted while fetching Status List Credential from: " + statusListCredentialUrl + ". " + e
            );
        } catch (IOException e) {
            throw new FailedCommunicationException(
                    "Error fetching Status List Credential from: " + statusListCredentialUrl + ". " + e
            );
        }

        if (response.statusCode() == 404) {
            throw new FailedCommunicationException(
                    "Status List Credential not found at: " + statusListCredentialUrl
            );
        }

        if (response.statusCode() != 200) {
            throw new FailedCommunicationException(
                    "Failed to fetch Status List Credential. Status code: " + response.statusCode()
                            + ", URL: " + statusListCredentialUrl
            );
        }

        return response.body();
    }

    private void validateStatusListCredentialCertificate(String jwtString, SignedJWT signedJwt) {
        final Map<String, Object> vcHeader = signedJwt.getHeader().toJSONObject();

        final String credentialIssuerDid;
        try {
            credentialIssuerDid = signedJwt.getJWTClaimsSet().getStringClaim("issuer");
        } catch (ParseException e) {
            throw new CredentialException("Error reading JWT claims: " + e.getMessage());
        }

        if (credentialIssuerDid == null || credentialIssuerDid.isBlank()) {
            throw new CredentialException("Missing or blank 'issuer' claim in Status List Credential JWT");
        }

        if (!credentialIssuerDid.startsWith("did:elsi:")) {
            throw new CredentialException("Unsupported issuer DID format. Expected 'did:elsi:...' but got: " + credentialIssuerDid);
        }

        final String certificateId = credentialIssuerDid.substring("did:elsi:".length());

        certificateValidationService.extractAndVerifyCertificate(jwtString, vcHeader, certificateId);

        log.debug("Status List Credential certificate validated successfully for issuer: {}", credentialIssuerDid);
    }

    private SignedJWT parseSignedJwt(String jwtString) {
        try {
            return SignedJWT.parse(jwtString);
        } catch (ParseException e) {
            throw new CredentialException("Error parsing Status List Credential JWT: " + e.getMessage());
        }
    }
}
