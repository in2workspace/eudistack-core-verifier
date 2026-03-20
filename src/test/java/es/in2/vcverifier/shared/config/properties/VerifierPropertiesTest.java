package es.in2.vcverifier.shared.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = VerifierPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
class VerifierPropertiesTest {

    @Autowired
    private VerifierProperties verifierProperties;

    @Test
    void testVerifierProperties() {
        VerifierProperties.Identity expectedIdentity = new VerifierProperties.Identity(
                "did:key:zDnaeTest",
                "0x73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5",
                ""
        );

        assertThat(verifierProperties.url())
                .as("Verifier URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(verifierProperties.portalUrl())
                .as("Portal URL should match")
                .isEqualTo("http://localhost:4200");

        assertThat(verifierProperties.identity())
                .as("Identity should match the provided values")
                .isEqualTo(expectedIdentity);
    }

    @Test
    void testMissingMandatoryUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.identity.private-key=test-private-key"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

    @Test
    void testPrivateKeyIsOptional() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.url=https://raw.githubusercontent.com"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                });
    }

    @Test
    void testIncludingAllProperties() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.url=https://raw.githubusercontent.com",
                        "verifier.identity.did-key=did:key:zTest",
                        "verifier.identity.private-key=test-private-key"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                });
    }

    @EnableConfigurationProperties(VerifierProperties.class)
    static class TestConfig {
    }
}
