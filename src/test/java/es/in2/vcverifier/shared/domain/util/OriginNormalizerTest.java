package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class OriginNormalizerTest {

    @Test
    void normalizeOrigin_mixedCaseSchemeAndHost_lowercases() {
        assertEquals("https://example.com", OriginNormalizer.normalizeOrigin("HTTPS://Example.Com/path"));
    }

    @Test
    void normalizeOrigin_explicitDefaultHttpsPort_dropsPort() {
        assertEquals("https://example.com", OriginNormalizer.normalizeOrigin("https://example.com:443/path"));
    }

    @Test
    void normalizeOrigin_explicitDefaultHttpPort_dropsPort() {
        assertEquals("http://example.com", OriginNormalizer.normalizeOrigin("http://example.com:80/path"));
    }

    @Test
    void normalizeOrigin_nonDefaultPort_keepsPort() {
        assertEquals("https://example.com:8443", OriginNormalizer.normalizeOrigin("https://example.com:8443/path"));
    }

    @Test
    void normalizeOrigin_malformedUri_returnsNull() {
        assertNull(OriginNormalizer.normalizeOrigin("not a uri"));
    }

    @Test
    void normalizeOrigin_blankOrNull_returnsNull() {
        assertNull(OriginNormalizer.normalizeOrigin(""));
        assertNull(OriginNormalizer.normalizeOrigin(null));
    }

    @Test
    void normalizeOrigin_missingHost_returnsNull() {
        assertNull(OriginNormalizer.normalizeOrigin("mailto:test@example.com"));
    }

    @Test
    void normalizeUri_mixedCaseSchemeAndHost_lowercasesButKeepsPath() {
        assertEquals("https://example.com/Path/Callback",
                OriginNormalizer.normalizeUri("HTTPS://Example.Com/Path/Callback"));
    }

    @Test
    void normalizeUri_defaultPort_dropsPortButKeepsQueryAndFragment() {
        assertEquals("https://example.com/cb?foo=bar#frag",
                OriginNormalizer.normalizeUri("https://Example.com:443/cb?foo=bar#frag"));
    }

    @Test
    void normalizeUri_nonDefaultPort_keepsPort() {
        assertEquals("https://example.com:8443/cb",
                OriginNormalizer.normalizeUri("https://Example.com:8443/cb"));
    }

    @Test
    void normalizeUri_malformedUri_returnsNull() {
        assertNull(OriginNormalizer.normalizeUri("not a uri"));
    }
}
