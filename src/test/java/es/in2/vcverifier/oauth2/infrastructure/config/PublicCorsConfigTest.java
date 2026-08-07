package es.in2.vcverifier.oauth2.infrastructure.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for {@link PublicCorsConfig}.
 *
 * <p>Validates that public endpoints ({@code /oid4vp/*}, {@code /api/login/*}, {@code /health})
 * allow wildcard origins, and that unconfigured paths return no CORS configuration.
 */
class PublicCorsConfigTest {

    private CorsConfigurationSource corsSource;

    @BeforeEach
    void setUp() {
        PublicCorsConfig config = new PublicCorsConfig();
        corsSource = config.publicCorsConfigurationSource();
    }

    @Test
    @DisplayName("OID4VP auth-request path returns wildcard origin config")
    void getCorsConfiguration_oid4vpAuthRequest_returnsWildcardConfig() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/auth-request/nonce-123");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("*"), corsConfig.getAllowedOriginPatterns());
    }

    @Test
    @DisplayName("OID4VP auth-response path returns wildcard origin config")
    void getCorsConfiguration_oid4vpAuthResponse_returnsWildcardConfig() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vp/auth-response");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("*"), corsConfig.getAllowedOriginPatterns());
    }

    @Test
    @DisplayName("Login API path returns wildcard origin config")
    void getCorsConfiguration_loginApi_returnsWildcardConfig() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login/events");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("*"), corsConfig.getAllowedOriginPatterns());
    }

    @Test
    @DisplayName("Health path returns wildcard origin config")
    void getCorsConfiguration_health_returnsWildcardConfig() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("*"), corsConfig.getAllowedOriginPatterns());
    }

    @Test
    @DisplayName("Unconfigured path returns null (no CORS config)")
    void getCorsConfiguration_unconfiguredPath_returnsNull() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/random/path");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNull(corsConfig);
    }

    @Test
    @DisplayName("Public CORS allows GET and POST methods")
    void getCorsConfiguration_publicEndpoint_allowsGetAndPost() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/auth-request/test");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("GET", "POST"), corsConfig.getAllowedMethods());
    }

    @Test
    @DisplayName("Public CORS allows Content-Type header")
    void getCorsConfiguration_publicEndpoint_allowsContentType() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vp/auth-response");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(List.of("Content-Type", "Authorization", "Cache-Control"), corsConfig.getAllowedHeaders());
    }

    @Test
    @DisplayName("Public CORS does not allow credentials")
    void getCorsConfiguration_publicEndpoint_credentialsNotAllowed() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertFalse(Boolean.TRUE.equals(corsConfig.getAllowCredentials()));
    }

    @Test
    @DisplayName("Wildcard origin pattern accepts any origin via checkOrigin")
    void checkOrigin_anyOrigin_returnsOrigin() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/auth-request/test");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals("https://any-wallet.example.com",
                corsConfig.checkOrigin("https://any-wallet.example.com"));
    }

    // =========================================================
    // /oid4vp/auth-response allowCredentials — EUDISTACK-548: SsoSessionAuthenticationSuccessHandler
    // sets the SSO session cookie as a Set-Cookie on this response; a browser only stores it on a
    // cross-origin response (wallet.* -> verifier.*) when this endpoint's CORS config answers
    // Access-Control-Allow-Credentials: true. With the endpoint sharing the other public
    // endpoints' allowCredentials(false), the cookie was silently discarded on every SSO
    // establishment — confirmed live (a valid, non-expired session existed in the DB, but every
    // reuse attempt received zero cookies).
    // =========================================================

    @Test
    @DisplayName("OID4VP auth-response path allows credentials, unlike the other public endpoints")
    void getCorsConfiguration_oid4vpAuthResponse_allowsCredentials() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vp/auth-response");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertEquals(Boolean.TRUE, corsConfig.getAllowCredentials());
    }

    @Test
    @DisplayName("OID4VP auth-response's credentialed wildcard still reflects the actual request origin")
    void checkOrigin_oid4vpAuthResponse_reflectsRequestOrigin() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vp/auth-response");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        // Spring only allows combining allowCredentials(true) with a *pattern* ("*" via
        // setAllowedOriginPatterns) because it reflects the caller's own Origin back per-request
        // instead of emitting a literal "*" — the literal form is what the CORS spec forbids
        // pairing with credentials. This asserts that reflection actually happens here.
        assertEquals("https://wallet-dome.127.0.0.1.nip.io:4443",
                corsConfig.checkOrigin("https://wallet-dome.127.0.0.1.nip.io:4443"));
    }

    @Test
    @DisplayName("Other public endpoints are unaffected — still no credentials")
    void getCorsConfiguration_oid4vpAuthRequest_stillNoCredentials() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/auth-request/nonce-123");

        CorsConfiguration corsConfig = corsSource.getCorsConfiguration(request);

        assertNotNull(corsConfig);
        assertFalse(Boolean.TRUE.equals(corsConfig.getAllowCredentials()));
    }
}
