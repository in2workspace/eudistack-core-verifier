package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Slf4j
@Component
@RequiredArgsConstructor
public class DssCertificateValidationClient {

    static final String VALIDATE_CERTIFICATE_PATH = "/services/rest/certificate-validation/validateCertificate";
    static final int MAX_RESPONSE_BYTES = 1024 * 1024;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final TrustValidationProperties trustValidationProperties;

    public JsonNode validateCertificate(X509Certificate certificate, List<X509Certificate> chain)
            throws DssUnavailableException {
        String url = trustValidationProperties.url();
        if (url == null || url.isBlank()) {
            log.warn("event=trust_validation_not_configured");
            throw new DssUnavailableException("Trust validation URL is not configured");
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(stripTrailingSlash(url) + VALIDATE_CERTIFICATE_PATH))
                    .timeout(trustValidationProperties.timeout())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody(certificate, chain)))
                    .build();
            HttpResponse<String> response = send(request);
            if (response.statusCode() != 200) {
                log.warn("event=trust_validation_failed status={}", response.statusCode());
                throw new DssUnavailableException("Trust validation answered with status " + response.statusCode());
            }
            return objectMapper.readTree(response.body());
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            log.warn("event=trust_validation_interrupted");
            throw new DssUnavailableException("Trust validation was interrupted");
        } catch (IOException | IllegalArgumentException | CertificateEncodingException e) {
            log.warn("event=trust_validation_failed error={}", e.getClass().getSimpleName());
            throw new DssUnavailableException("Trust validation failed: " + e.getClass().getSimpleName());
        }
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<String>> exchange = httpClient.sendAsync(request, _ ->
                HttpResponse.BodySubscribers.mapping(new BoundedBodySubscriber(MAX_RESPONSE_BYTES),
                        bytes -> new String(bytes, StandardCharsets.UTF_8)));
        try {
            return exchange.get(trustValidationProperties.timeout().toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException _) {
            exchange.cancel(true);
            throw new HttpTimeoutException("Trust validation did not finish within the timeout");
        } catch (ExecutionException e) {
            throw e.getCause() instanceof IOException cause ? cause : new IOException(e.getCause());
        }
    }

    private String requestBody(X509Certificate certificate, List<X509Certificate> chain)
            throws CertificateEncodingException, IOException {
        ObjectNode body = objectMapper.createObjectNode();
        body.set("certificate", remoteCertificate(certificate));
        ArrayNode certificateChain = body.putArray("certificateChain");
        for (X509Certificate chainCertificate : chain) {
            certificateChain.add(remoteCertificate(chainCertificate));
        }
        body.put("tokenExtractionStrategy", "NONE");
        return objectMapper.writeValueAsString(body);
    }

    private ObjectNode remoteCertificate(X509Certificate certificate) throws CertificateEncodingException {
        return objectMapper.createObjectNode()
                .put("encodedCertificate", Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
