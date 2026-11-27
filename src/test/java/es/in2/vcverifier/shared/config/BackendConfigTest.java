package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

import java.util.List;
import java.util.Set;

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
    void getUrl_withRequestContext_returnsBaseWithContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("kpmg.eudistack.net");
        request.setServerPort(443);
        request.setContextPath("/verifier");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(backendConfig.getUrl()).isEqualTo("https://kpmg.eudistack.net/verifier");
    }

    @Test
    void getUrl_withXTenantHeader_stillReturnsBaseWithContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("verifier.kpmg.com");
        request.setServerPort(443);
        request.setContextPath("/verifier");
        request.addHeader("X-Tenant", "kpmg");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(backendConfig.getUrl()).isEqualTo("https://verifier.kpmg.com/verifier");
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

        assertThat(backendConfig.getLoginEventStreamTimeoutSeconds())
                .as("Login SSE stream should outlive the login timeout by the grace period")
                .isEqualTo(150L);

        assertThat(backendConfig.isFapiNonceRequired())
                .as("FAPI nonce required should match configured value")
                .isTrue();
    }

    @Test
    void getTrustedVerifierOrigins_noAdditionalUrls_returnsOnlyCanonicalUrl() {
        assertThat(backendConfig.getTrustedVerifierOrigins())
                .containsExactly("https://raw.githubusercontent.com");
    }

    @Test
    void getTrustedVerifierOrigins_withAdditionalUrls_returnsNormalizedOrigins() {
        BackendProperties properties = new BackendProperties(
                "https://Verifier.Example.com:443",
                List.of("https://kpmg.eudistack.net"),
                null, null, null, null, null, null, null, null, null, null);
        BackendConfig config = new BackendConfig(properties);

        assertThat(config.getTrustedVerifierOrigins())
                .containsExactlyInAnyOrder("https://verifier.example.com", "https://kpmg.eudistack.net");
    }

    @Test
    void getStaticUrl_withAdditionalUrls_returnsCanonicalUrlOnly() {
        BackendProperties properties = new BackendProperties(
                "https://verifier.example.com",
                List.of("https://kpmg.eudistack.net"),
                null, null, null, null, null, null, null, null, null, null);
        BackendConfig config = new BackendConfig(properties);

        assertThat(config.getStaticUrl()).isEqualTo("https://verifier.example.com");
    }

    @Test
    void getAllUrls_withAdditionalUrls_returnsCanonicalFirstThenAdditional() {
        BackendProperties properties = new BackendProperties(
                "https://verifier.example.com",
                List.of("https://kpmg.eudistack.net", "https://dome.example.com"),
                null, null, null, null, null, null, null, null, null, null);
        BackendConfig config = new BackendConfig(properties);

        assertThat(config.getAllUrls())
                .containsExactly("https://verifier.example.com", "https://kpmg.eudistack.net", "https://dome.example.com");
    }

    @Test
    void getAllUrls_noAdditionalUrls_returnsOnlyCanonicalUrl() {
        assertThat(backendConfig.getAllUrls()).containsExactly("https://raw.githubusercontent.com");
    }

    @Test
    void getSsoCredentialEncryptionKey_ssoConfigured_returnsKey() {
        BackendProperties properties = new BackendProperties(
                "https://verifier.example.com",
                List.of(),
                null, null, null, null, null, null, null,
                new BackendProperties.Sso("base64-encoded-key"), null, null);
        BackendConfig config = new BackendConfig(properties);

        assertThat(config.getSsoCredentialEncryptionKey()).isEqualTo("base64-encoded-key");
    }

    @Test
    void getSsoCredentialEncryptionKey_ssoNotConfigured_returnsNull() {
        BackendProperties properties = new BackendProperties(
                "https://verifier.example.com",
                List.of(),
                null, null, null, null, null, null, null, null, null, null);
        BackendConfig config = new BackendConfig(properties);

        assertThat(config.getSsoCredentialEncryptionKey()).isNull();
    }

    private static BackendConfig backendConfigWithLoginTimes(Long loginTimeout, Long selectionTimeout, Long expiryMargin) {
        return new BackendConfig(new BackendProperties(
                "https://verifier.example.com",
                List.of(),
                null, null, null, null, loginTimeout, null, null, null, selectionTimeout, expiryMargin));
    }

    @Nested
    @DisplayName("getPendingLoginRetentionSeconds")
    class PendingLoginRetention {

        @Test
        void getPendingLoginRetentionSeconds_nothingConfigured_returnsSelectionTimeoutPlusDefaultMargin() {
            // Arrange
            BackendConfig config = backendConfigWithLoginTimes(null, null, null);

            // Act
            long retention = config.getPendingLoginRetentionSeconds();

            // Assert
            assertThat(retention).isEqualTo(1200L);
        }

        @Test
        void getPendingLoginRetentionSeconds_customMargin_addsItToTheSelectionTimeout() {
            // Arrange
            BackendConfig config = backendConfigWithLoginTimes(null, null, 300L);

            // Act
            long retention = config.getPendingLoginRetentionSeconds();

            // Assert
            assertThat(retention).isEqualTo(900L);
        }

        @Test
        void getPendingLoginRetentionSeconds_zeroMargin_keepsTheLoginUntilItsLongestExpiry() {
            // Arrange
            BackendConfig config = backendConfigWithLoginTimes(null, null, 0L);

            // Act
            long retention = config.getPendingLoginRetentionSeconds();

            // Assert
            assertThat(retention).isEqualTo(600L);
        }

        @Test
        void getPendingLoginRetentionSeconds_customSelectionTimeout_followsIt() {
            // Arrange
            BackendConfig config = backendConfigWithLoginTimes(null, 900L, null);

            // Act
            long retention = config.getPendingLoginRetentionSeconds();

            // Assert
            assertThat(retention).isEqualTo(1500L);
        }

        @Test
        void getPendingLoginRetentionSeconds_qrTimeoutLongerThanSelection_usesTheLongerOne() {
            // Arrange
            BackendConfig config = backendConfigWithLoginTimes(900L, 300L, 100L);

            // Act
            long retention = config.getPendingLoginRetentionSeconds();

            // Assert
            assertThat(retention).isEqualTo(1000L);
        }

        @ParameterizedTest
        @ValueSource(longs = {-1L, 3601L, Long.MAX_VALUE})
        void loginExpiryMarginSeconds_outOfRange_isRejectedByValidation(long margin) {
            // Arrange
            Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

            // Act
            Set<ConstraintViolation<BackendProperties>> violations = validator.validate(propertiesWithMargin(margin));

            // Assert
            assertThat(violations)
                    .extracting(violation -> violation.getPropertyPath().toString())
                    .containsExactly("loginExpiryMarginSeconds");
        }

        @ParameterizedTest
        @ValueSource(longs = {0L, 3600L})
        void loginExpiryMarginSeconds_withinRange_passesValidation(long margin) {
            // Arrange
            Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

            // Act
            Set<ConstraintViolation<BackendProperties>> violations = validator.validate(propertiesWithMargin(margin));

            // Assert
            assertThat(violations).isEmpty();
        }

        private BackendProperties propertiesWithMargin(long margin) {
            return new BackendProperties(
                    "https://verifier.example.com",
                    List.of(),
                    null, null, null, null, null, null, null, null, null, margin);
        }
    }

    @Configuration
    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
