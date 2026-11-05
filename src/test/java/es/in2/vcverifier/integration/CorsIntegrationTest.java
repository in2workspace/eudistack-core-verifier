package es.in2.vcverifier.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for CORS policy enforcement on the Verifier's security filter chains.
 *
 * <p>Public endpoints ({@code /oid4vp/*}, {@code /api/login/*}, {@code /health}) allow any
 * origin (wildcard) via {@code PublicCorsConfig}.
 *
 * <p>OIDC endpoints ({@code /oidc/*}) restrict origins to registered clients via
 * {@code RegisteredClientsCorsConfig}. Those CORS rules are tested at the unit level in
 * {@code RegisteredClientsCorsConfigTest} because the Authorization Server filter chain's
 * request matcher does not intercept OPTIONS preflight requests in MockMvc
 */
@SpringBootTest(
        properties = {
                "spring.flyway.enabled=false",
                "verifier.certificate-login.tenants.cgcom.host=cgcom-cert.example.com",
                "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.example.com",
                "verifier.certificate-login.subject-key=0123456789abcdef0123456789abcdef"
        }
)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CorsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    // --- Public endpoints: wildcard CORS ---

    @Nested
    @DisplayName("Public endpoints (wildcard CORS)")
    class PublicEndpointsCors {

        @Test
        @DisplayName("OID4VP auth-request endpoint allows any origin")
        void oid4vpAuthRequest_anyOrigin_corsAllowed() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-request/test-nonce")
                            .header("Origin", "https://any-wallet.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("OID4VP short request-object endpoint allows any origin")
        void oid4vpShortRequestObject_anyOrigin_corsAllowed() throws Exception {
            mockMvc.perform(options("/oid4vp/r/test-id")
                            .header("Origin", "https://any-wallet.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("OID4VP auth-response endpoint allows any origin")
        void oid4vpAuthResponse_anyOrigin_corsAllowed() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-response")
                            .header("Origin", "https://another-wallet.example.com")
                            .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("Login API endpoint allows any origin")
        void loginEndpoint_anyOrigin_corsAllowed() throws Exception {
            mockMvc.perform(options("/api/login/events")
                            .header("Origin", "https://any-spa.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("Health endpoint allows any origin")
        void healthEndpoint_anyOrigin_corsAllowed() throws Exception {
            mockMvc.perform(options("/health")
                            .header("Origin", "https://monitoring.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("Public endpoint echoes requesting origin (allowedOriginPatterns=*)")
        void publicEndpoint_anyOrigin_echosOriginBack() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-request/test-nonce")
                            .header("Origin", "https://unique-wallet.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin",
                            "https://unique-wallet.example.com"));
        }

        @Test
        @DisplayName("Public endpoint CORS allows GET and POST methods")
        void publicEndpoint_allowedMethods_returnsGetAndPost() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-request/test-nonce")
                            .header("Origin", "https://wallet.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Methods", "GET,POST"));
        }

        @Test
        @DisplayName("Public endpoint CORS rejects non-allowed method (DELETE)")
        void publicEndpoint_disallowedMethod_rejectsDelete() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-request/test-nonce")
                            .header("Origin", "https://wallet.example.com")
                            .header("Access-Control-Request-Method", "DELETE"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Public endpoint CORS allows Content-Type header")
        void publicEndpoint_contentTypeHeader_allowed() throws Exception {
            mockMvc.perform(options("/oid4vp/auth-response")
                            .header("Origin", "https://wallet.example.com")
                            .header("Access-Control-Request-Method", "POST")
                            .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().exists("Access-Control-Allow-Headers"));
        }

        @Test
        @DisplayName("Unconfigured path rejects CORS preflight")
        void unconfiguredPath_anyOrigin_corsRejected() throws Exception {
            mockMvc.perform(options("/some/random/path")
                            .header("Origin", "https://wallet.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("Certificate login on the certificate port (exact login origin)")
    class CertificateLoginCors {

        @Test
        @DisplayName("allows the login origin of the tenant, with credentials")
        void certificateLogin_loginOriginOfItsTenant_corsAllowedWithCredentials() throws Exception {
            mockMvc.perform(options("/api/login/certificate")
                            .with(onCertificatePort("cgcom-cert.example.com"))
                            .header("Origin", "https://cgcom.example.com")
                            .header("Access-Control-Request-Method", "POST")
                            .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "https://cgcom.example.com"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        }

        @Test
        @DisplayName("rejects any other origin")
        void certificateLogin_otherOrigin_corsRejected() throws Exception {
            mockMvc.perform(options("/api/login/certificate")
                            .with(onCertificatePort("cgcom-cert.example.com"))
                            .header("Origin", "https://any-spa.example.com")
                            .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden())
                    .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("rejects the login origin of the tenant on the host of another tenant")
        void certificateLogin_originOfAnotherTenant_corsRejected() throws Exception {
            mockMvc.perform(options("/api/login/certificate")
                            .with(onCertificatePort("kpmg-cert.example.com"))
                            .header("Origin", "https://cgcom.example.com")
                            .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden())
                    .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("rejects a method other than POST")
        void certificateLogin_otherMethod_corsRejected() throws Exception {
            mockMvc.perform(options("/api/login/certificate")
                            .with(onCertificatePort("cgcom-cert.example.com"))
                            .header("Origin", "https://cgcom.example.com")
                            .header("Access-Control-Request-Method", "PUT"))
                    .andExpect(status().isForbidden());
        }

        private RequestPostProcessor onCertificatePort(String host) {
            return request -> {
                request.setServerName(host);
                request.setLocalPort(CertificateLoginProperties.DEFAULT_PORT);
                return request;
            };
        }
    }
}
