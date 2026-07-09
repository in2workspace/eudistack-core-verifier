package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class OriginNormalizerTest {

    @Test
    void normalize_mixedCaseSchemeAndHost_lowercases() {
        assertEquals(URI.create("https://example.com"), OriginNormalizer.normalize("HTTPS://Example.Com/path"));
    }

    @Test
    void normalize_explicitDefaultHttpsPort_dropsPort() {
        assertEquals(URI.create("https://example.com"), OriginNormalizer.normalize("https://example.com:443/path"));
    }

    @Test
    void normalize_explicitDefaultHttpPort_dropsPort() {
        assertEquals(URI.create("http://example.com"), OriginNormalizer.normalize("http://example.com:80/path"));
    }

    @Test
    void normalize_nonDefaultPort_keepsPort() {
        assertEquals(URI.create("https://example.com:8443"), OriginNormalizer.normalize("https://example.com:8443/path"));
    }

    @Test
    void normalize_malformedUri_returnsNull() {
        assertNull(OriginNormalizer.normalize("not a uri"));
    }

    @Test
    void normalize_blankOrNull_returnsNull() {
        assertNull(OriginNormalizer.normalize(""));
        assertNull(OriginNormalizer.normalize((String) null));
    }

    @Test
    void normalize_missingHost_returnsNull() {
        assertNull(OriginNormalizer.normalize("mailto:test@example.com"));
    }

    @Test
    void normalize_uriOverload_producesSameResultAsStringOverload() {
        assertEquals(OriginNormalizer.normalize("HTTPS://Example.Com:443/path"),
                OriginNormalizer.normalize(URI.create("HTTPS://Example.Com:443/path")));
    }

    @Test
    void normalize_nullUri_returnsNull() {
        assertNull(OriginNormalizer.normalize((URI) null));
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
