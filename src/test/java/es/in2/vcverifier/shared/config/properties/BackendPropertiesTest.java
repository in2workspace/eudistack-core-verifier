package es.in2.vcverifier.shared.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = BackendPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
class BackendPropertiesTest {

    @Autowired
    private BackendProperties backendProperties;

    @Test
    void testBackendProperties() {
        BackendProperties.Identity expectedIdentity = new BackendProperties.Identity(
                "did:key:zDnaeTest",
                "0x73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5",
                ""
        );

        assertThat(backendProperties.url())
                .as("Backend URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(backendProperties.identity())
                .as("Identity should match the provided private key")
                .isEqualTo(expectedIdentity);
    }

    @Test
    void testMissingMandatoryUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        // Omit url:
                        "verifier.backend.identity.privateKey=test-private-key"
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
                        "verifier.backend.url=https://raw.githubusercontent.com"
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
                        "verifier.backend.url=https://raw.githubusercontent.com",
                        "verifier.backend.identity.didKey=did:key:zTest",
                        "verifier.backend.identity.privateKey=test-private-key"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                });
    }

    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
