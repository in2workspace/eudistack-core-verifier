package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import es.in2.vcverifier.verifier.domain.port.CertificateTrustValidationPort;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DssCertificateTrustValidationAdapter implements CertificateTrustValidationPort {

    static final String VALIDATE_CERTIFICATE_PATH = "/services/rest/certificate-validation/validateCertificate";
    private static final ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.97");

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final TrustValidationProperties trustValidationProperties;
    private final Clock clock;

    @Override
    public CertificateTrust validate(X509Certificate certificate, List<X509Certificate> chain) {
        String url = trustValidationProperties.url();
        if (url == null || url.isBlank()) {
            log.warn("event=trust_validation_not_configured");
            return new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(stripTrailingSlash(url) + VALIDATE_CERTIFICATE_PATH))
                    .timeout(trustValidationProperties.timeout())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody(certificate, chain)))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("event=trust_validation_failed status={}", response.statusCode());
                return new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
            }
            CertificateTrust trust = DssReportTranslator.translate(objectMapper.readTree(response.body()),
                    hasOrganizationIdentifier(certificate), clock.instant(), trustValidationProperties.maxListAge());
            log.info("event=trust_validation_done result={}", describe(trust));
            return trust;
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            log.warn("event=trust_validation_interrupted");
            return new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        } catch (IOException | IllegalArgumentException | CertificateEncodingException e) {
            log.warn("event=trust_validation_failed error={}", e.getClass().getSimpleName());
            return new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
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

    private static boolean hasOrganizationIdentifier(X509Certificate certificate) {
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        return subject.getRDNs(ORGANIZATION_IDENTIFIER).length > 0;
    }

    private static String describe(CertificateTrust trust) {
        return switch (trust) {
            case CertificateTrust.Trusted(AssuranceLevel level, _) -> "trusted level=" + level.name();
            case CertificateTrust.Rejected(CertificateLoginReason reason) -> reason.value();
        };
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
