package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateSubjectServiceTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final CertificateLoginProperties CGCOM_WITH_X509 = new CertificateLoginProperties(null, Map.of(
            "cgcom", new CertificateLoginProperties.Tenant("https://cgcom.example.com")));
    private static final CertificateLoginProperties NO_X509 = new CertificateLoginProperties(null, null);

    private final CertificateSubjectService service = new CertificateSubjectService(KEY, CGCOM_WITH_X509);

    @Test
    void subject_isTheBase64UrlHmacOfTenantCountryAndNumber() {
        assertThat(service.subject("cgcom", "ES", "12345678Z")).isEqualTo("LfEbdGXk2FmckCMUkeVYVlSLNiRRXbH4wxQJRqd_6xA");
    }

    @Test
    void subject_isStableForTheSamePersonAndTenant() {
        assertThat(service.subject("cgcom", "ES", "12345678Z"))
                .isEqualTo(new CertificateSubjectService(KEY, CGCOM_WITH_X509).subject("cgcom", "ES", "12345678Z"));
    }

    @Test
    void subject_differsInAnotherTenant() {
        assertThat(service.subject("kpmg", "ES", "12345678Z")).isEqualTo("SiX6Q5E2EaueiJk89-f_C590korvZY5feBH1Ebi2uSI");
    }

    @Test
    void subject_doesNotContainTheNumber() {
        assertThat(service.subject("cgcom", "ES", "12345678Z")).doesNotContain("12345678");
    }

    @Test
    void subject_requiresTenantCountryAndNumber() {
        assertThatThrownBy(() -> service.subject("cgcom", null, "12345678Z")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.subject(" ", "ES", "12345678Z")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.subject("cgcom", "ES", null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void withoutX509_startsWithoutKeyButCannotDeriveSubjects() {
        CertificateSubjectService withoutKey = new CertificateSubjectService("", NO_X509);

        assertThatThrownBy(() -> withoutKey.subject("cgcom", "ES", "12345678Z")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void withX509_doesNotStartWithoutKeyAndNamesTheMissingKey() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.example.com")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().rootCause()
                        .hasMessageContaining(CertificateSubjectService.SUBJECT_KEY_VARIABLE)
                        .hasMessageContaining("cgcom")
                        .hasMessageNotContaining(KEY));
    }

    @Test
    void withX509_doesNotStartWithAShortKey() {
        assertThatThrownBy(() -> new CertificateSubjectService("too-short", CGCOM_WITH_X509))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("shorter than " + CertificateSubjectService.MIN_KEY_BYTES)
                .hasMessageNotContaining("too-short");
    }

    @Test
    void withX509_startsWithTheKey() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.certificate-login.tenants.cgcom.login-origin=https://cgcom.example.com",
                        CertificateSubjectService.SUBJECT_KEY_PROPERTY + "=" + KEY)
                .run(context -> assertThat(context.getBean(CertificateSubjectService.class)
                        .subject("cgcom", "ES", "12345678Z")).isEqualTo("LfEbdGXk2FmckCMUkeVYVlSLNiRRXbH4wxQJRqd_6xA"));
    }

    @Configuration
    @EnableConfigurationProperties(CertificateLoginProperties.class)
    @Import(CertificateSubjectService.class)
    static class TestConfig {
    }
}
