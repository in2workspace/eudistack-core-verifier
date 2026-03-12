package es.in2.vcverifier.shared.domain.util;

import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafeUrlValidatorTest {

    private final SafeUrlValidator validator = new SafeUrlValidator();

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void shouldRejectNullOrBlankUrl(String url) {
        assertThatThrownBy(() -> validator.validate(url))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void shouldRejectFileScheme() {
        assertThatThrownBy(() -> validator.validate("file:///etc/passwd"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("scheme not allowed");
    }

    @Test
    void shouldRejectFtpScheme() {
        assertThatThrownBy(() -> validator.validate("ftp://example.com/file"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("scheme not allowed");
    }

    @Test
    void shouldRejectLoopbackAddress() {
        assertThatThrownBy(() -> validator.validate("http://127.0.0.1/admin"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Loopback");
    }

    @Test
    void shouldRejectLocalhost() {
        assertThatThrownBy(() -> validator.validate("http://localhost/admin"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Loopback");
    }

    @Test
    void shouldRejectPrivateNetworkClassA() {
        assertThatThrownBy(() -> validator.validate("http://10.0.0.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectPrivateNetworkClassB() {
        assertThatThrownBy(() -> validator.validate("http://172.16.0.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectPrivateNetworkClassC() {
        assertThatThrownBy(() -> validator.validate("http://192.168.1.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectLinkLocalAddress() {
        assertThatThrownBy(() -> validator.validate("http://169.254.1.1/metadata"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Link-local");
    }

    @Test
    void shouldRejectAwsMetadataEndpoint() {
        assertThatThrownBy(() -> validator.validate("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(SsrfProtectionException.class);
    }

    @Test
    void shouldRejectUrlWithoutHost() {
        assertThatThrownBy(() -> validator.validate("http:///path"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("valid host");
    }

    @Test
    void shouldAcceptPublicHttpsUrl() {
        assertThatCode(() -> validator.validate("https://8.8.8.8/status-list/1"))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldAcceptPublicHttpUrl() {
        assertThatCode(() -> validator.validate("http://8.8.8.8/status-list/1"))
                .doesNotThrowAnyException();
    }
}
