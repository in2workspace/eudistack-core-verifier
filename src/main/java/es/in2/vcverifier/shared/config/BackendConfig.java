package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class BackendConfig {

    private static final long LOGIN_EVENT_STREAM_GRACE_SECONDS = 30L;

    private final BackendProperties properties;

    public String getUrl() {
        try {
            ServletRequestAttributes attrs =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                String scheme = request.getScheme();
                String host = request.getServerName();
                int port = request.getServerPort();
                String contextPath = request.getContextPath();
                boolean defaultPort = ("https".equals(scheme) && port == 443)
                        || ("http".equals(scheme) && port == 80);
                return scheme + "://" + host + (defaultPort ? "" : ":" + port) + contextPath;
            }
        } catch (Exception ignored) {
            // No request context (startup, async, etc.) — use static config
        }
        return properties.url();
    }

    public String getStaticUrl() {
        return properties.url();
    }

    public List<String> getAllUrls() {
        List<String> additional = properties.additionalUrls();
        if (additional == null || additional.isEmpty()) {
            return List.of(properties.url());
        }
        List<String> all = new ArrayList<>(additional.size() + 1);
        all.add(properties.url());
        all.addAll(additional);
        return List.copyOf(all);
    }

    public Set<String> getTrustedVerifierOrigins() {
        return getAllUrls().stream()
                .map(OriginNormalizer::normalize)
                .filter(Objects::nonNull)
                .map(URI::toString)
                .collect(Collectors.toUnmodifiableSet());
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

    public String getSsoCredentialEncryptionKey() {
        return properties.sso() != null ? properties.sso().credentialEncryptionKey() : null;
    }

    public boolean hasIdentityConfigured() {
        return properties.identity() != null
                && properties.identity().privateKey() != null
                && !properties.identity().privateKey().isBlank();
    }

    private BackendProperties.TrustFramework getSelectedTrustFramework() {
        return properties.getDOMETrustFrameworkByName();
    }

    public String getTrustedIssuerListUri() {
        return getSelectedTrustFramework().trustedIssuersListUrl();
    }

    public String getClientsRepositoryUri() {
        return getSelectedTrustFramework().trustedServicesListUrl();
    }

    public List<BackendProperties.TrustFramework> getAllTrustFrameworks() {
        return properties.trustFrameworks();
    }

    public String getLocalClientsPath() {
        return properties.localFiles() != null ? properties.localFiles().clientsPath() : null;
    }

    public String getLocalTrustedIssuersPath() {
        return properties.localFiles() != null ? properties.localFiles().trustedIssuersPath() : null;
    }

    public String getLocalSchemasDir() {
        return properties.localFiles() != null ? properties.localFiles().schemasDir() : null;
    }

    public long getLoginTimeoutSeconds() {
        return properties.loginTimeoutSeconds() != null ? properties.loginTimeoutSeconds() : 120L;
    }

    /**
     * Lifetime of the login SSE stream: the login timeout plus a grace period. A presentation
     * accepted just before the timeout may still be under validation (revocation checks, etc.)
     * when the browser's countdown ends; the browser keeps listening while it aborts the login,
     * so the redirect carrying the authorization code must still be deliverable. Closing the
     * stream is also what ends the browser's wait for such a late completion.
     */
    public long getLoginEventStreamTimeoutSeconds() {
        return getLoginTimeoutSeconds() + LOGIN_EVENT_STREAM_GRACE_SECONDS;
    }

    public boolean isFapiNonceRequired() {
        return properties.fapiNonceRequired() != null ? properties.fapiNonceRequired() : true;
    }

    public boolean isX5cChainValidationBypassed() {
        return properties.x5cChainValidation() != null
                && Boolean.TRUE.equals(properties.x5cChainValidation().bypass());
    }

    public boolean isAiaChasingEnabled() {
        return properties.x5cChainValidation() == null
                || properties.x5cChainValidation().aiaChasing() == null
                || properties.x5cChainValidation().aiaChasing().enabled() == null
                || Boolean.TRUE.equals(properties.x5cChainValidation().aiaChasing().enabled());
    }

    public long getAccessTokenExpirationSeconds() {
        return properties.tokenExpiration() != null ? properties.tokenExpiration().accessTokenSeconds() : 900;
    }

    public long getIdTokenExpirationSeconds() {
        return properties.tokenExpiration() != null ? properties.tokenExpiration().idTokenSeconds() : 60;
    }

    public long getRefreshTokenExpirationSeconds() {
        return properties.tokenExpiration() != null ? properties.tokenExpiration().refreshTokenSeconds() : 43200;
    }
}
