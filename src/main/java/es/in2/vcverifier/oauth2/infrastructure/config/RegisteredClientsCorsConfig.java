package es.in2.vcverifier.oauth2.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class RegisteredClientsCorsConfig {

    private final Set<String> allowedClientsOrigins;

    @Bean
    public CorsConfigurationSource registeredClientsCorsConfigurationSource() {
        // Build the CorsConfiguration dynamically on each request so that origins
        // added by ClientLoaderConfig (initial load + scheduled refresh) are always
        // reflected without requiring an application restart.
        // Discovery and public-key endpoints (/.well-known/**, /oidc/jwks) must be
        // reachable from any origin — they are public infrastructure by spec.
        return request -> {
            String path = request.getServletPath();
            if (path.startsWith("/.well-known/") || "/oidc/jwks".equals(path)) {
                CorsConfiguration publicConfig = new CorsConfiguration();
                publicConfig.addAllowedOriginPattern("*"); //NOSONAR: discovery/JWKS endpoints are intentionally public
                publicConfig.setAllowedMethods(List.of("GET"));
                publicConfig.setAllowedHeaders(List.of("Content-Type", "Authorization", "Cache-Control"));
                publicConfig.setAllowCredentials(false);
                return publicConfig;
            }
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(new ArrayList<>(allowedClientsOrigins));
            config.setAllowedMethods(List.of("GET", "POST"));
            config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
            config.setAllowCredentials(false);
            return config;
        };
    }
}