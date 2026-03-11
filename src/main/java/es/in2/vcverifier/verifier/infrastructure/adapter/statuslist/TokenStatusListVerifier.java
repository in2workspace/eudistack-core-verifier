package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import es.in2.vcverifier.verifier.domain.model.TokenStatusListData;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

/**
 * Verifies credential revocation using Token Status List (draft-ietf-oauth-status-list).
 * Used for SD-JWT credentials with status.status_list references.
 *
 * Token Status List JWT format:
 * - Header typ: "statuslist+jwt"
 * - Payload: { "status_list": { "bits": 1, "lst": "<base64url-gzip>" } }
 * - No multibase prefix on lst (unlike BitstringStatusList)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenStatusListVerifier implements CredentialStatusVerifier {

    private static final String SUPPORTED_TYPE = "TokenStatusListEntry";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Override
    public boolean supports(String credentialStatusType) {
        return SUPPORTED_TYPE.equals(credentialStatusType);
    }

    @Override
    public boolean isRevoked(String statusListUrl, String statusIndex, String expectedPurpose) {
        log.info("Checking credential revocation in token status list - URL: {}, Index: {}",
                statusListUrl, statusIndex);

        final int index = parseAndValidateIndex(statusIndex);

        final String jwtString = fetchTokenStatusListJwt(statusListUrl);
        log.debug("Token Status List JWT fetched successfully");

        final TokenStatusListData statusData = parseTokenStatusList(jwtString);
        log.debug("Token Status List parsed. bitsPerEntry: {}", statusData.bitsPerEntry());

        final int totalEntries = (statusData.rawBytes().length * 8) / statusData.bitsPerEntry();
        if (index >= totalEntries) {
            throw new CredentialException(
                    "statusListIndex out of range. totalEntries=" + totalEntries + ", index=" + index
            );
        }

        final boolean isRevoked = isStatusSet(statusData.rawBytes(), index, statusData.bitsPerEntry());

        log.info("Token Status List revocation check completed. Index: {}, IsRevoked: {}", index, isRevoked);

        return isRevoked;
    }

    TokenStatusListData parseTokenStatusList(String jwtString) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(jwtString);
            JsonNode claimsNode = objectMapper.valueToTree(
                    signedJwt.getJWTClaimsSet().toJSONObject()
            );

            JsonNode statusListNode = claimsNode.get("status_list");
            if (statusListNode == null || statusListNode.isNull() || !statusListNode.isObject()) {
                throw new StatusListCredentialException("Missing or invalid 'status_list' in Token Status List JWT");
            }

            JsonNode bitsNode = statusListNode.get("bits");
            if (bitsNode == null || !bitsNode.isNumber()) {
                throw new StatusListCredentialException("Missing or invalid 'bits' in status_list");
            }
            int bits = bitsNode.intValue();

            JsonNode lstNode = statusListNode.get("lst");
            if (lstNode == null || !lstNode.isTextual() || lstNode.asText().isBlank()) {
                throw new StatusListCredentialException("Missing or invalid 'lst' in status_list");
            }

            byte[] rawBytes = decodeLst(lstNode.asText());

            String issuer = signedJwt.getJWTClaimsSet().getIssuer();

            return new TokenStatusListData(issuer, bits, rawBytes);

        } catch (ParseException e) {
            throw new StatusListCredentialException("Error parsing Token Status List JWT", e);
        }
    }

    /**
     * Checks whether the status value at the given index is non-zero.
     * For 1-bit entries: 1 = revoked, 0 = valid.
     * For multi-bit entries: any non-zero value = revoked/suspended.
     */
    boolean isStatusSet(byte[] rawBytes, int index, int bitsPerEntry) {
        if (rawBytes == null) {
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        if (index < 0) {
            throw new StatusListCredentialException("index must be >= 0");
        }

        int bitOffset = index * bitsPerEntry;
        int value = 0;

        for (int i = 0; i < bitsPerEntry; i++) {
            int currentBitIndex = bitOffset + i;
            int byteIndex = currentBitIndex / 8;
            int bitInByte = 7 - (currentBitIndex % 8);

            if (byteIndex >= rawBytes.length) {
                throw new StatusListCredentialException(
                        "Bit index out of range. byteIndex=" + byteIndex + ", rawBytesLength=" + rawBytes.length
                );
            }

            int bit = (rawBytes[byteIndex] >> bitInByte) & 1;
            value = (value << 1) | bit;
        }

        return value != 0;
    }

    /**
     * Decodes the lst field: base64url → gzip → raw bytes.
     * No multibase prefix (unlike BitstringStatusList encodedList).
     */
    private byte[] decodeLst(String lst) {
        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(lst.trim());
        } catch (IllegalArgumentException e) {
            throw new StatusListCredentialException("lst is not valid base64url: " + e.getMessage());
        }
        return gunzip(gzipped);
    }

    private byte[] gunzip(byte[] input) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = gzip.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new StatusListCredentialException("Failed to gunzip Token Status List content", e);
        }
    }

    private int parseAndValidateIndex(String statusIndex) {
        final int index;
        try {
            index = Integer.parseInt(statusIndex);
        } catch (NumberFormatException e) {
            throw new CredentialException(
                    "statusListIndex " + statusIndex + " is not a valid integer: " + e.getMessage()
            );
        }
        if (index < 0) {
            throw new CredentialException("statusListIndex must be >= 0, but was: " + statusIndex);
        }
        return index;
    }

    private String fetchTokenStatusListJwt(String statusListUrl) {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusListUrl))
                .header("Accept", "application/statuslist+jwt")
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException(
                    "Interrupted while fetching Token Status List from: " + statusListUrl + ". " + e
            );
        } catch (IOException e) {
            throw new FailedCommunicationException(
                    "Error fetching Token Status List from: " + statusListUrl + ". " + e
            );
        }

        if (response.statusCode() == 404) {
            throw new FailedCommunicationException(
                    "Token Status List not found at: " + statusListUrl
            );
        }

        if (response.statusCode() != 200) {
            throw new FailedCommunicationException(
                    "Failed to fetch Token Status List. Status code: " + response.statusCode()
                            + ", URL: " + statusListUrl
            );
        }

        return response.body();
    }
}
