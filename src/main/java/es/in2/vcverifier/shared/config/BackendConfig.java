package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class BackendConfig {

    private final BackendProperties properties;

    /**
     * Returns the verifier's external URL. When called during HTTP request processing
     * with forwarded headers (e.g. behind nginx), derives the URL from the original
     * request (scheme + host + port). Falls back to the static configuration value
     * when no request context is available (e.g. during bean initialization).
     *
     * <p>{@code verifier.backend.url} is the canonical URL, used as issuer/audience/
     * response_uri. Additional alias domains (SSO multi-tenant/multi-app) are configured
     * separately via {@code verifier.backend.additional-urls} — see {@link #getAllUrls()}
     * and {@link #getTrustedVerifierOrigins()} for the full set.
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

    /**
     * Returns the static configured canonical URL ({@code verifier.backend.url}),
     * ignoring the request context.
     */
    public String getStaticUrl() {
        return properties.url();
    }

    /**
     * Returns the canonical {@code url} followed by every configured {@code additionalUrls}
     * entry (alias domains for SSO multi-tenant/multi-app deployments), in that order.
     */
    public List<String> getAllUrls() {
        List<String> additional = properties.additionalUrls();
        if (additional == null || additional.isEmpty()) {
            return List.of(properties.url());
        }
        List<String> all = new ArrayList<>();
        all.add(properties.url());
        all.addAll(additional);
        return List.copyOf(all);
    }

    /**
     * Returns the set of origins the verifier is allowed to redirect to for its own
     * internal pages (e.g. /login, /error), normalized for case and default ports.
     *
     * <p>Deliberately static and configuration-driven — never derived from the current
     * request's Host, even one resolved via a trusted reverse proxy, so a single
     * misconfigured or compromised hop in front of the verifier cannot widen the set of
     * trusted redirect targets. Derived from {@link #getAllUrls()} (canonical {@code url}
     * plus {@code additionalUrls}).
     */
    public Set<String> getTrustedVerifierOrigins() {
        return getAllUrls().stream()
                .map(OriginNormalizer::normalizeOrigin)
                .filter(Objects::nonNull)
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

    // todo currently unused, will be used when Verifier can manage multiple trustframeworks
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

    public boolean isFapiNonceRequired() {
        return properties.fapiNonceRequired() != null ? properties.fapiNonceRequired() : true;
    }

    /**
     * Returns true only when the operator has explicitly opted out of x5c chain validation.
     * Null or false (the default) means chain validation is active (secure-by-default).
     */
    public boolean isX5cChainValidationBypassed() {
        return properties.x5cChainValidation() != null
                && Boolean.TRUE.equals(properties.x5cChainValidation().bypass());
    }

    /**
     * Returns true unless the operator has explicitly set aia-chasing.enabled=false.
     * Enabled by default so QTSP tokens with leaf-only x5c are handled automatically.
     */
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
