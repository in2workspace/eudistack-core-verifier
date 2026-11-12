package es.in2.vcverifier.shared.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateLoginPropertiesTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void binds_theCertificateLoginEntryOfEachTenant() {
        runner.withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.stg.eudistack.net")
                .run(context -> {
                    CertificateLoginProperties properties = context.getBean(CertificateLoginProperties.class);
                    assertThat(properties.tenants()).containsOnlyKeys("cgcom");
                    assertThat(properties.tenants().get("cgcom").loginOrigin()).isEqualTo("https://cgcom.stg.eudistack.net");
                });
    }

    @Test
    void binds_noTenantsAndTheDefaultPortWhenNothingIsConfigured() {
        runner.run(context -> {
            CertificateLoginProperties properties = context.getBean(CertificateLoginProperties.class);
            assertThat(properties.tenants()).isEmpty();
            assertThat(properties.port()).isEqualTo(8081);
        });
    }

    @Test
    void binds_theConfiguredPort() {
        runner.withPropertyValues("verifier.certificate-login.port=9443")
                .run(context -> assertThat(context.getBean(CertificateLoginProperties.class).port()).isEqualTo(9443));
    }

    @Test
    void fails_whenAnEntryHasNoLoginOrigin() {
        runner.withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void fails_whenTheLoginOriginIsNotAUrl() {
        runner.withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=not a url")
                .run(context -> assertThat(context).hasFailed());
    }

    @Configuration
    @EnableConfigurationProperties(CertificateLoginProperties.class)
    static class TestConfig {
    }
}
