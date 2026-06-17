package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {BackendConfig.class, BackendConfigTest.TestConfig.class})
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class BackendConfigTest {

    @Autowired
    private BackendConfig backendConfig;

    @BeforeEach
    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void getUrl_canonical_returnsBaseWithContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("kpmg.eudistack.net");
        request.setServerPort(443);
        request.setContextPath("/verifier");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(backendConfig.getUrl()).isEqualTo("https://kpmg.eudistack.net/verifier");
    }

    @Test
    void getUrl_nonCanonical_returnsBaseWithoutContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("verifier.kpmg.com");
        request.setServerPort(443);
        request.setContextPath("/verifier");
        request.addHeader("X-Tenant", "kpmg");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(backendConfig.getUrl()).isEqualTo("https://verifier.kpmg.com");
    }

    @Test
    void getUrl_noRequestContext_returnsStaticUrl() {
        assertThat(backendConfig.getUrl()).isEqualTo("https://raw.githubusercontent.com");
    }

    @Test
    void testBackendConfig() {
        assertThat(backendConfig.getStaticUrl())
                .as("Backend URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

     assertThat(backendConfig.getPrivateKey())
        .as("Private key should remove 0x prefix")
        .isEqualTo("73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");

        assertThat(backendConfig.getTrustedIssuerListUri())
                .as("Trusted Issuer List URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(backendConfig.getClientsRepositoryUri())
                .as("Clients Repository URI should match")
                .isEqualTo("https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml");

        assertThat(backendConfig.getLoginTimeoutSeconds())
                .as("Login timeout should match configured value")
                .isEqualTo(120L);

        assertThat(backendConfig.isFapiNonceRequired())
                .as("FAPI nonce required should match configured value")
                .isTrue();
    }

    @Configuration
    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
