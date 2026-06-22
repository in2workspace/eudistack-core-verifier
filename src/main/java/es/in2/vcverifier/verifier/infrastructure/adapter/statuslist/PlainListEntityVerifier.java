package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

// Adapter for DOME's legacy "PlainListEntity" credentialStatus type. The
// status list at `statusListCredential` is a plain JSON array of
// { "nonce": "<id>" } entries; a credential is revoked when its
// statusListIndex (a nonce string) appears in that array. No JWT, no
// signature and no statusPurpose — DOME only uses these lists for
// revocation during the legacy sunset window.
@Slf4j
@Component
@RequiredArgsConstructor
public class PlainListEntityVerifier implements CredentialStatusVerifier {

    private static final String SUPPORTED_TYPE = "PlainListEntity";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final SafeUrlValidator safeUrlValidator;
    private final ObjectMapper objectMapper;

    @Override
    public boolean supports(String credentialStatusType) {
        return SUPPORTED_TYPE.equals(credentialStatusType);
    }

    @Override
    public boolean isRevoked(String statusListUrl, String statusIndex, String expectedPurpose) {
        log.info("Checking credential revocation in DOME plain list - URL: {}, Index: {}",
                statusListUrl, statusIndex);

        if (statusIndex == null || statusIndex.isBlank()) {
            throw new CredentialException("PlainListEntity statusListIndex is missing or blank");
        }

        safeUrlValidator.validate(statusListUrl);

        final List<Map<String, Object>> entries = fetchPlainList(statusListUrl);

        final boolean isRevoked = entries.stream()
                .anyMatch(entry -> statusIndex.equals(entry.get("nonce")));

        log.info("PlainList revocation check completed. Index: {}, IsRevoked: {}",
                statusIndex, isRevoked);
        return isRevoked;
    }

    private List<Map<String, Object>> fetchPlainList(String statusListUrl) {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusListUrl))
                .header("Accept", "application/json")
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException(
                    "Interrupted while fetching DOME plain list from: " + statusListUrl + ". " + e);
        } catch (IOException e) {
            throw new FailedCommunicationException(
                    "Error fetching DOME plain list from: " + statusListUrl + ". " + e);
        }

        if (response.statusCode() == 404) {
            throw new FailedCommunicationException(
                    "DOME plain list not found at: " + statusListUrl);
        }
        if (response.statusCode() != 200) {
            throw new FailedCommunicationException(
                    "Failed to fetch DOME plain list. Status code: " + response.statusCode()
                            + ", URL: " + statusListUrl);
        }

        try {
            return objectMapper.readValue(response.body(), new TypeReference<>() {});
        } catch (IOException e) {
            throw new CredentialException(
                    "Failed to parse DOME plain list from " + statusListUrl + ": " + e.getMessage());
        }
    }
}
