package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiaCertificateChainResolverImpl implements AiaCertificateChainResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final int MAX_DEPTH = 10;
    private static final int MAX_RESPONSE_BYTES = 1_048_576; // 1 MB DoS guard (SEC-S3)

    private final HttpClient httpClient;
    private final SafeUrlValidator safeUrlValidator;
    private final BackendConfig backendConfig;
    private final CacheStore<List<X509Certificate>> aiaCertCacheStore;

    @Override
    public List<X509Certificate> completeChain(List<X509Certificate> x5cChain) {
        if (!backendConfig.isAiaChasingEnabled() || x5cChain == null || x5cChain.isEmpty()) {
            return x5cChain;
        }

        List<X509Certificate> work = new ArrayList<>(x5cChain);
        Set<String> seen = new HashSet<>();
        x5cChain.forEach(c -> seen.add(fingerprint(c)));
        boolean chasingOccurred = false;

        while (true) {
            X509Certificate top = work.get(work.size() - 1);
            if (isSelfSigned(top)) {
                break;
            }
            if (work.size() >= MAX_DEPTH) {
                log.warn("AIA chasing reached MAX_DEPTH ({}) without finding a self-signed root — stopping. " +
                         "Top cert issuer: {}", MAX_DEPTH, top.getIssuerX500Principal().getName());
                break;
            }
            Optional<String> caIssuersUrl = extractCaIssuersUrl(top);
            if (caIssuersUrl.isEmpty()) {
                log.debug("No http(s) caIssuers URL in AIA extension — stopping. " +
                          "Top cert subject: {}", top.getSubjectX500Principal().getName());
                break;
            }
            String url = caIssuersUrl.get();
            // SEC-14: SSRF protection before every outbound fetch
            safeUrlValidator.validate(url);

            List<X509Certificate> fetched = getCachedOrFetch(url);
            // TODO: AKI/SKI tie-break when multiple candidates share the same subject DN
            Optional<X509Certificate> issuerCert = fetched.stream()
                    .filter(c -> c.getSubjectX500Principal().equals(top.getIssuerX500Principal()))
                    .findFirst();
            if (issuerCert.isEmpty()) {
                log.warn("AIA fetch from {} returned {} cert(s) but none matched issuer DN '{}' — stopping",
                         url, fetched.size(), top.getIssuerX500Principal().getName());
                break;
            }
            String fp = fingerprint(issuerCert.get());
            if (seen.contains(fp)) {
                log.warn("AIA chasing detected a cycle at URL {} — stopping to prevent infinite loop", url);
                break;
            }
            work.add(issuerCert.get());
            seen.add(fp);
            chasingOccurred = true;
        }

        if (chasingOccurred) {
            X509Certificate root = work.get(work.size() - 1);
            if (isSelfSigned(root)) {
                log.warn("AIA chasing reached self-signed root '{}' (fingerprint: {}) that was NOT supplied in x5c " +
                         "— accepted WITHOUT trust-anchor pinning (weaker security). " +
                         "Configure a trust store to restrict accepted roots (EUDISTACK roadmap).",
                         root.getSubjectX500Principal().getName(), fingerprint(root));
            }
        }

        return work;
    }

    private Optional<String> extractCaIssuersUrl(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null) {
            return Optional.empty();
        }
        try {
            byte[] aiaBytes = ASN1OctetString.getInstance(extensionValue).getOctets();
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaBytes);
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (X509ObjectIdentifiers.id_ad_caIssuers.equals(ad.getAccessMethod())) {
                    GeneralName gn = ad.getAccessLocation();
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = gn.getName().toString();
                        if (url.startsWith("http")) {
                            return Optional.of(url);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse AIA extension from cert '{}': {}",
                     cert.getSubjectX500Principal().getName(), e.getMessage());
        }
        return Optional.empty();
    }

    private List<X509Certificate> getCachedOrFetch(String url) {
        try {
            return aiaCertCacheStore.get(url);
        } catch (NoSuchElementException e) {
            List<X509Certificate> certs = fetchAndParse(url);
            aiaCertCacheStore.add(url, certs);
            return certs;
        }
    }

    private static final int MAX_REDIRECTS = 3;

    private List<X509Certificate> fetchAndParse(String originalUrl) {
        String url = originalUrl;
        for (int redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/pkix-cert, application/pkcs7-mime, application/x-x509-ca-cert")
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();

            HttpResponse<byte[]> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new FailedCommunicationException(
                        "Interrupted while fetching CA cert from AIA URL: " + url);
            } catch (IOException e) {
                throw new FailedCommunicationException(
                        "Error fetching CA cert from AIA URL: " + url + ". " + e.getMessage());
            }

            int status = response.statusCode();
            if (status == 301 || status == 302 || status == 307 || status == 308) {
                String location = response.headers().firstValue("Location").orElse(null);
                if (location == null) {
                    throw new FailedCommunicationException(
                            "AIA URL " + url + " returned " + status + " with no Location header");
                }
                // SEC-14: SSRF check on redirect target before following
                safeUrlValidator.validate(location);
                log.debug("AIA redirect {} -> {}", url, location);
                url = location;
                continue;
            }
            if (status == 404) {
                throw new FailedCommunicationException("CA cert not found at AIA URL: " + url);
            }
            if (status != 200) {
                throw new FailedCommunicationException(
                        "Failed to fetch CA cert from AIA URL: " + url + ". Status: " + status);
            }
            return parseCerts(response.body(), url);
        }
        throw new FailedCommunicationException(
                "Too many redirects fetching CA cert from AIA URL: " + originalUrl);
    }

    private List<X509Certificate> parseCerts(byte[] body, String url) {
        if (body.length > MAX_RESPONSE_BYTES) {
            throw new CertificateChainValidationException(
                    "AIA response from " + url + " exceeds maximum size (" + MAX_RESPONSE_BYTES + " bytes)");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(body));
            return certs.stream()
                    .filter(c -> c instanceof X509Certificate)
                    .map(c -> (X509Certificate) c)
                    .toList();
        } catch (CertificateException e) {
            throw new CertificateChainValidationException(
                    "Failed to parse certificate(s) from AIA URL " + url + ": " + e.getMessage(), e);
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static String fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(cert.getEncoded()));
        } catch (Exception e) {
            return cert.getSubjectX500Principal().getName();
        }
    }
}
