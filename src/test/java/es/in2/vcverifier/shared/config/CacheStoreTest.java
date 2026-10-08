package es.in2.vcverifier.shared.config;
import es.in2.vcverifier.shared.config.CacheStore;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class CacheStoreTest {

    private CacheStore<String> cache;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Test
    void add_and_get_success() {
        cache.add("key1", "value1");
        assertEquals("value1", cache.get("key1"));
    }

    @Test
    void get_missingKey_throwsNoSuchElementException() {
        assertThrows(NoSuchElementException.class, () -> cache.get("nonexistent"));
    }

    @Test
    void delete_removesEntry() {
        cache.add("key1", "value1");
        cache.delete("key1");
        assertThrows(NoSuchElementException.class, () -> cache.get("key1"));
    }

    @Test
    void add_nullKey_returnsNull() {
        assertNull(cache.add(null, "value"));
    }

    @Test
    void add_blankKey_returnsNull() {
        assertNull(cache.add("  ", "value"));
    }

    @Test
    void add_nullValue_returnsNull() {
        assertNull(cache.add("key", null));
    }

    @Test
    void add_validEntry_returnsKey() {
        String result = cache.add("key1", "value1");
        assertEquals("key1", result);
    }

    @Test
    void add_overwritesExistingKey() {
        cache.add("key1", "first");
        cache.add("key1", "second");
        assertEquals("second", cache.get("key1"));
    }

    @Test
    void expiry_entryDisappearsAfterExpiry() throws InterruptedException {
        CacheStore<String> shortCache = new CacheStore<>(1, TimeUnit.SECONDS);
        shortCache.add("key1", "value1");
        assertEquals("value1", shortCache.get("key1"));

        Thread.sleep(1500);
        assertThrows(NoSuchElementException.class, () -> shortCache.get("key1"));
    }

    // ---- EUD-252 (F1): atomic primitives backing the single in-flight login per state ----

    @Test
    void putIfAbsent_existingEntry_keepsOriginalAndReturnsIt() {
        assertNull(cache.putIfAbsent("state", "victim"));
        assertEquals("victim", cache.putIfAbsent("state", "attacker"));
        assertEquals("victim", cache.get("state"));
    }

    @Test
    void replace_onlyWhenStillExpected() {
        cache.add("state", "first");
        assertFalse(cache.replace("state", "stale", "other"));
        assertTrue(cache.replace("state", "first", "retry"));
        assertEquals("retry", cache.get("state"));
    }

    @Test
    void remove_returnsValueOnce() {
        cache.add("h", "pending");
        assertEquals("pending", cache.remove("h"));
        assertNull(cache.remove("h"));
    }

    @Test
    void putIfAbsent_concurrentWriters_exactlyOneWins() throws Exception {
        int writers = 32;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(writers);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger winners = new java.util.concurrent.atomic.AtomicInteger();
        java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < writers; i++) {
            String value = "browser-" + i;
            futures.add(pool.submit(() -> {
                start.await();
                if (cache.putIfAbsent("contended-state", value) == null) {
                    winners.incrementAndGet();
                }
                return null;
            }));
        }
        start.countDown();
        for (java.util.concurrent.Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(1, winners.get());
    }

    @Test
    void replace_concurrentRetriesFromSameOriginal_exactlyOneWins() throws Exception {
        cache.add("state", "original");
        int writers = 32;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(writers);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger winners = new java.util.concurrent.atomic.AtomicInteger();
        java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < writers; i++) {
            String value = "retry-" + i;
            futures.add(pool.submit(() -> {
                start.await();
                if (cache.replace("state", "original", value)) {
                    winners.incrementAndGet();
                }
                return null;
            }));
        }
        start.countDown();
        for (java.util.concurrent.Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(1, winners.get());
    }
}
