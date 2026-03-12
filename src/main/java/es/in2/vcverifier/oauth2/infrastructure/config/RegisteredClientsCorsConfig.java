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
        return request -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(new ArrayList<>(allowedClientsOrigins));
            config.setAllowedMethods(List.of("GET", "POST"));
            config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
            config.setAllowCredentials(false);
            return config;
        };
    }
}