package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.VerifierProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {VerifierConfig.class, VerifierConfigTest.TestConfig.class})
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class VerifierConfigTest {

    @Autowired
    private VerifierConfig verifierConfig;

    @Test
    void testVerifierConfig() {
        assertThat(verifierConfig.getStaticUrl())
                .as("Verifier URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(verifierConfig.getPrivateKey())
                .as("Private key should remove 0x prefix")
                .isEqualTo("73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");
    }

    @Test
    void testGetPortalUrl_isNotNull() {
        assertThat(verifierConfig.getPortalUrl())
                .as("Portal URL should not be null")
                .isNotNull();
    }

    @Configuration
    @EnableConfigurationProperties(VerifierProperties.class)
    static class TestConfig {
    }
}
