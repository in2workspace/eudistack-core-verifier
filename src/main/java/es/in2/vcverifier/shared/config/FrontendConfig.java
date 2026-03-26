package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FrontendConfig {

    private final FrontendProperties properties;

    /**
     * Returns the verifier frontend portal URL.
     * Always uses the static VERIFIER_PORTAL_URL configuration.
     * Multi-tenant dynamic resolution will be redesigned separately.
     */
    public String getPortalUrl() {
        return properties.portalUrl();
    }
}
