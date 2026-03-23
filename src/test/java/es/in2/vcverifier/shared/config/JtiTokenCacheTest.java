package es.in2.vcverifier.shared.config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class JtiTokenCacheTest {

    private JtiTokenCache jtiTokenCache;

    @BeforeEach
    void setUp() {
        jtiTokenCache = new JtiTokenCache(new CacheStore<>(1800, TimeUnit.SECONDS));
    }

    @Test
    void isJtiPresent_empty_returnsFalse() {
        assertFalse(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void addJti_thenIsPresent_returnsTrue() {
        jtiTokenCache.addJti("jti-1");
        assertTrue(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void addJti_duplicateDoesNotFail() {
        jtiTokenCache.addJti("jti-1");
        jtiTokenCache.addJti("jti-1");
        assertTrue(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void isJtiPresent_differentJti_returnsFalse() {
        jtiTokenCache.addJti("jti-1");
        assertFalse(jtiTokenCache.isJtiPresent("jti-2"));
    }

    @Test
    void isJtiPresent_afterTtlExpires_returnsFalse() throws InterruptedException {
        JtiTokenCache shortLivedCache = new JtiTokenCache(new CacheStore<>(1, TimeUnit.SECONDS));
        shortLivedCache.addJti("jti-expiring");
        assertTrue(shortLivedCache.isJtiPresent("jti-expiring"));

        Thread.sleep(1500);

        assertFalse(shortLivedCache.isJtiPresent("jti-expiring"));
    }
}
