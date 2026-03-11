package es.in2.vcverifier.shared.domain.util;

import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafeUrlValidatorTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void shouldRejectNullOrBlankUrl(String url) {
        assertThatThrownBy(() -> SafeUrlValidator.validate(url))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void shouldRejectFileScheme() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("file:///etc/passwd"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("scheme not allowed");
    }

    @Test
    void shouldRejectFtpScheme() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("ftp://example.com/file"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("scheme not allowed");
    }

    @Test
    void shouldRejectLoopbackAddress() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://127.0.0.1/admin"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Loopback");
    }

    @Test
    void shouldRejectLocalhost() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://localhost/admin"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Loopback");
    }

    @Test
    void shouldRejectPrivateNetworkClassA() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://10.0.0.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectPrivateNetworkClassB() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://172.16.0.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectPrivateNetworkClassC() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://192.168.1.1/internal"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Private network");
    }

    @Test
    void shouldRejectLinkLocalAddress() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://169.254.1.1/metadata"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("Link-local");
    }

    @Test
    void shouldRejectAwsMetadataEndpoint() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(SsrfProtectionException.class);
    }

    @Test
    void shouldRejectUrlWithoutHost() {
        assertThatThrownBy(() -> SafeUrlValidator.validate("http:///path"))
                .isInstanceOf(SsrfProtectionException.class)
                .hasMessageContaining("valid host");
    }

    @Test
    void shouldAcceptPublicHttpsUrl() {
        assertThatCode(() -> SafeUrlValidator.validate("https://example.com/status-list/1"))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldAcceptPublicHttpUrl() {
        assertThatCode(() -> SafeUrlValidator.validate("http://example.com/status-list/1"))
                .doesNotThrowAnyException();
    }
}
