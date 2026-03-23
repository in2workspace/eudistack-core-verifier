package es.in2.vcverifier.oauth2.infrastructure.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link RegisteredClientsCorsConfig}.
 *
 * <p>Validates that the CORS configuration source for OIDC endpoints dynamically
 * reflects the allowed origins from the client registry.
 */
class RegisteredClientsCorsConfigTest {

    private Set<String> allowedOrigins;
    private CorsConfigurationSource corsSource;

    @BeforeEach
    void setUp() {
        allowedOrigins = Collections.synchronizedSet(new HashSet<>());
        RegisteredClientsCorsConfig config = new RegisteredClientsCorsConfig(allowedOrigins);
        corsSource = config.registeredClientsCorsConfigurationSource();
    }

    @Test
    @DisplayName("Returns CORS config with registered origin")
    void getCorsConfiguration_registeredOrigin_returnsOriginInConfig() {
        allowedOrigins.add("https://client.example.com");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        List<String> origins = corsConfig.getAllowedOrigins();
        assertNotNull(origins);
        assertTrue(origins.contains("https://client.example.com"));
    }

    @Test
    @DisplayName("Returns empty origins when no clients are registered")
    void getCorsConfiguration_noRegisteredClients_returnsEmptyOrigins() {
        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        List<String> origins = corsConfig.getAllowedOrigins();
        assertNotNull(origins);
        assertTrue(origins.isEmpty());
    }

    @Test
    @DisplayName("Reflects dynamically added origins on subsequent calls")
    void getCorsConfiguration_originAddedAfterInit_reflectsNewOrigin() {
        // First call: no origins
        CorsConfiguration firstConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());
        assertNotNull(firstConfig);
        assertTrue(firstConfig.getAllowedOrigins().isEmpty());

        // Add origin dynamically (simulates ClientLoaderConfig refresh)
        allowedOrigins.add("https://new-client.example.com");

        // Second call: new origin reflected
        CorsConfiguration secondConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());
        assertNotNull(secondConfig);
        assertTrue(secondConfig.getAllowedOrigins().contains("https://new-client.example.com"));
    }

    @Test
    @DisplayName("Allows only GET and POST methods")
    void getCorsConfiguration_allowedMethods_onlyGetAndPost() {
        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertEquals(List.of("GET", "POST"), corsConfig.getAllowedMethods());
    }

    @Test
    @DisplayName("Allows Content-Type and Authorization headers")
    void getCorsConfiguration_allowedHeaders_contentTypeAndAuthorization() {
        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertEquals(List.of("Content-Type", "Authorization"), corsConfig.getAllowedHeaders());
    }

    @Test
    @DisplayName("Credentials are not allowed")
    void getCorsConfiguration_allowCredentials_isFalse() {
        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertFalse(Boolean.TRUE.equals(corsConfig.getAllowCredentials()));
    }

    @Test
    @DisplayName("Unregistered origin is not in allowed origins")
    void getCorsConfiguration_unregisteredOrigin_notInAllowedOrigins() {
        allowedOrigins.add("https://good-client.example.com");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertFalse(corsConfig.getAllowedOrigins().contains("https://evil-site.example.com"));
    }

    @Test
    @DisplayName("Validates actual CORS check rejects unregistered origin")
    void checkOrigin_unregisteredOrigin_returnsNull() {
        allowedOrigins.add("https://good-client.example.com");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertNull(corsConfig.checkOrigin("https://evil-site.example.com"));
    }

    @Test
    @DisplayName("Validates actual CORS check accepts registered origin")
    void checkOrigin_registeredOrigin_returnsOrigin() {
        allowedOrigins.add("https://good-client.example.com");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        assertEquals("https://good-client.example.com",
                corsConfig.checkOrigin("https://good-client.example.com"));
    }

    @Test
    @DisplayName("Multiple registered origins are all present")
    void getCorsConfiguration_multipleOrigins_allPresent() {
        allowedOrigins.add("https://client-a.example.com");
        allowedOrigins.add("https://client-b.example.com");
        allowedOrigins.add("https://client-c.example.com");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(new MockHttpServletRequest());

        assertNotNull(corsConfig);
        List<String> origins = corsConfig.getAllowedOrigins();
        assertEquals(3, origins.size());
        assertTrue(origins.containsAll(Set.of(
                "https://client-a.example.com",
                "https://client-b.example.com",
                "https://client-c.example.com")));
    }
}
