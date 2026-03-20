package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.VerifierProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
@RequiredArgsConstructor
public class VerifierConfig {

    private final VerifierProperties properties;

    /**
     * Returns the verifier's external URL. When called during HTTP request processing
     * with forwarded headers (e.g. behind nginx), derives the URL from the original
     * request (scheme + host + port). Falls back to the static configuration value
     * when no request context is available (e.g. during bean initialization).
     */
    public String getUrl() {
        try {
            ServletRequestAttributes attrs =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                String scheme = request.getScheme();
                String host = request.getServerName();
                int port = request.getServerPort();
                boolean defaultPort = ("https".equals(scheme) && port == 443)
                        || ("http".equals(scheme) && port == 80);
                return scheme + "://" + host + (defaultPort ? "" : ":" + port);
            }
        } catch (Exception ignored) {
            // No request context (startup, async, etc.) — use static config
        }
        return properties.url();
    }

    /**
     * Returns the static configured URL, ignoring the request context.
     */
    public String getStaticUrl() {
        return properties.url();
    }

    /**
     * Returns the verifier frontend portal URL. In multi-tenant mode (behind nginx),
     * the portal URL is the same as the backend's external URL (same host, same port).
     * Falls back to the static configuration when no request context is available.
     */
    public String getPortalUrl() {
        String dynamicUrl = getUrl();
        // If dynamic resolution worked (returned a URL different from the static backend URL),
        // use it — the frontend is served on the same host:port as the OIDC endpoints.
        if (!dynamicUrl.equals(getStaticUrl())) {
            return dynamicUrl;
        }
        return properties.portalUrl();
    }

    public String getPrivateKey() {
        String privateKey = properties.identity() != null ? properties.identity().privateKey() : null;
        if (privateKey != null && privateKey.startsWith("0x")) {
            privateKey = privateKey.substring(2);
        }
        return privateKey;
    }

    public String getDidKey() {
        return properties.identity() != null ? properties.identity().didKey() : null;
    }

    public String getCertificate() {
        return properties.identity() != null ? properties.identity().certificate() : null;
    }

    public boolean hasIdentityConfigured() {
        return properties.identity() != null
                && properties.identity().privateKey() != null
                && !properties.identity().privateKey().isBlank();
    }

    public String getLocalClientsPath() {
        return properties.files() != null ? properties.files().clients() : null;
    }

    public String getLocalTrustedIssuersPath() {
        return properties.files() != null ? properties.files().trustedIssuers() : null;
    }

    public String getLocalSchemasDir() {
        return properties.files() != null ? properties.files().schemas() : null;
    }

    public long getAccessTokenExpirationSeconds() {
        return properties.token() != null ? properties.token().accessTokenTtl() : 900;
    }

    public long getIdTokenExpirationSeconds() {
        return properties.token() != null ? properties.token().idTokenTtl() : 60;
    }

    public long getRefreshTokenExpirationSeconds() {
        return properties.token() != null ? properties.token().refreshTokenTtl() : 43200;
    }
}
