package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FrontendConfig {

    private final FrontendProperties properties;
    private final BackendConfig backendConfig;

    /**
     * Returns the verifier frontend portal URL. In multi-tenant mode (behind nginx),
     * the portal URL is the same as the backend's external URL (same host, same port).
     * Falls back to the static configuration when no request context is available.
     */
    public String getPortalUrl() {
        String dynamicUrl = backendConfig.getUrl();
        // If dynamic resolution worked (returned a URL different from the static backend URL),
        // use it — the frontend is served on the same host:port as the OIDC endpoints.
        if (!dynamicUrl.equals(backendConfig.getStaticUrl())) {
            return dynamicUrl;
        }
        return properties.portalUrl();
    }
}
