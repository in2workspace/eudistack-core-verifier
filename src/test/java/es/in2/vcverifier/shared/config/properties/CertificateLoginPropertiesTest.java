package es.in2.vcverifier.shared.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateLoginPropertiesTest {

    private static final String SECURE_ORIGIN = "s3cr3t-0f-th3-s3cur3-0r1g1n-d1str1but10n";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void binds_theSecureOriginAndTheCertificateLoginEntryOfEachTenant() {
        runner.withPropertyValues(
                        "verifier.certificate-login.secure-origin=" + SECURE_ORIGIN,
                        "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.stg.eudistack.net")
                .run(context -> {
                    CertificateLoginProperties properties = context.getBean(CertificateLoginProperties.class);
                    assertThat(properties.secureOrigin()).isEqualTo(SECURE_ORIGIN);
                    assertThat(properties.tenants()).containsOnlyKeys("cgcom");
                    assertThat(properties.tenants().get("cgcom").loginOrigin()).isEqualTo("https://cgcom.stg.eudistack.net");
                });
    }

    @Test
    void binds_noTenantsNorSecureOriginWhenNothingIsConfigured() {
        runner.run(context -> {
            CertificateLoginProperties properties = context.getBean(CertificateLoginProperties.class);
            assertThat(properties.tenants()).isEmpty();
            assertThat(properties.secureOrigin()).isNull();
        });
    }

    @Test
    void fails_whenTenantsAreConfiguredWithoutSecureOrigin() {
        runner.withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.stg.eudistack.net")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().rootCause()
                        .hasMessageContaining(CertificateLoginProperties.SECURE_ORIGIN_VARIABLE)
                        .hasMessageContaining("cgcom"));
    }

    @Test
    void fails_whenTheSecureOriginIsTooShort() {
        Map<String, CertificateLoginProperties.Tenant> tenants =
                Map.of("cgcom", new CertificateLoginProperties.Tenant("https://cgcom.stg.eudistack.net"));

        assertThatThrownBy(() -> new CertificateLoginProperties("abc123", tenants))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(CertificateLoginProperties.SECURE_ORIGIN_VARIABLE)
                .hasMessageNotContaining("abc123");
    }

    @Test
    void fails_whenAnEntryHasNoLoginOrigin() {
        runner.withPropertyValues(
                        "verifier.certificate-login.secure-origin=" + SECURE_ORIGIN,
                        "verifier.certificate-login.tenants.cgcom.login-origin=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void fails_whenTheLoginOriginIsNotAUrl() {
        runner.withPropertyValues(
                        "verifier.certificate-login.secure-origin=" + SECURE_ORIGIN,
                        "verifier.certificate-login.tenants.cgcom.login-origin=not a url")
                .run(context -> assertThat(context).hasFailed());
    }

    @Configuration
    @EnableConfigurationProperties(CertificateLoginProperties.class)
    static class TestConfig {
    }
}
