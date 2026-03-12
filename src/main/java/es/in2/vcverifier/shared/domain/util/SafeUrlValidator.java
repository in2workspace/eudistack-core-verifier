package es.in2.vcverifier.shared.domain.util;

import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * SEC-14: SSRF protection — validates URLs before outbound HTTP requests.
 * Rejects private/internal IPs, non-HTTP schemes, and malformed URIs.
 */
@Slf4j
@Component
public class SafeUrlValidator {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");

    /**
     * Validates that the given URL is safe for outbound HTTP requests.
     *
     * @param url the URL to validate
     * @throws SsrfProtectionException if the URL is unsafe
     */
    public void validate(String url) {
        if (url == null || url.isBlank()) {
            throw new SsrfProtectionException("URL must not be null or blank");
        }

        final URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new SsrfProtectionException("Malformed URL: " + e.getMessage());
        }

        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new SsrfProtectionException("URL scheme not allowed: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new SsrfProtectionException("URL must have a valid host");
        }

        validateHostNotPrivate(host);
    }

    private void validateHostNotPrivate(String host) {
        final InetAddress address;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            throw new SsrfProtectionException("Cannot resolve host: " + host);
        }

        if (address.isLoopbackAddress()) {
            throw new SsrfProtectionException("Loopback addresses are not allowed");
        }

        if (address.isLinkLocalAddress()) {
            throw new SsrfProtectionException("Link-local addresses are not allowed");
        }

        if (address.isSiteLocalAddress()) {
            throw new SsrfProtectionException("Private network addresses are not allowed");
        }

        if (address.isAnyLocalAddress()) {
            throw new SsrfProtectionException("Wildcard addresses are not allowed");
        }

        // Block AWS metadata endpoint (169.254.169.254)
        byte[] addrBytes = address.getAddress();
        if (addrBytes.length == 4 && (addrBytes[0] & 0xFF) == 169 && (addrBytes[1] & 0xFF) == 254) {
            throw new SsrfProtectionException("Cloud metadata addresses are not allowed");
        }

        log.debug("URL host validated as safe: {}", host);
    }
}
