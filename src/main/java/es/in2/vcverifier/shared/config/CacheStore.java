package es.in2.vcverifier.shared.config;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.RequiredArgsConstructor;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
public class CacheStore<T> {

    private static final long DEFAULT_MAX_SIZE = 10_000L;

    private final Cache<String, T> cache;

    public CacheStore(long expiryDuration, TimeUnit timeUnit) {
        this(expiryDuration, timeUnit, DEFAULT_MAX_SIZE);
    }

    // SEC-S3: All caches MUST have maximumSize to prevent memory exhaustion (DoS).
    public CacheStore(long expiryDuration, TimeUnit timeUnit, long maximumSize) {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryDuration, timeUnit)
                .maximumSize(maximumSize)
                .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                .build();
    }

    public T get(String key) {
        T value = cache.getIfPresent(key);
        if (value != null) {
            return value;
        } else {
            throw new NoSuchElementException("Value is not present.");
        }
    }

    /** Same lookup as {@link #get(String)} but returns {@code null} instead of throwing on a miss. */
    public T getIfPresent(String key) {
        return cache.getIfPresent(key);
    }

    public void delete(String key) {
        cache.invalidate(key);
    }

    /**
     * Atomically removes and returns the value for {@code key} ({@code null} on a miss or expiry):
     * of several concurrent callers for the same key, at most one gets the value (single use) —
     * unlike {@link #getIfPresent(String)} followed by {@link #delete(String)}, where all may.
     */
    public T remove(String key) {
        return cache.asMap().remove(key);
    }

    /**
     * Atomically removes the entry for {@code key} only if it is still {@code expected}.
     *
     * @return whether the removal happened
     */
    public boolean remove(String key, T expected) {
        return cache.asMap().remove(key, expected);
    }

    /**
     * Atomically stores {@code value} only if no live (non-expired) entry exists for {@code key}.
     *
     * @return {@code null} if the value was stored, otherwise the entry already in place (unchanged)
     */
    public T putIfAbsent(String key, T value) {
        return cache.asMap().putIfAbsent(key, value);
    }

    /**
     * Atomically replaces the entry for {@code key} only if it is still {@code expected}.
     *
     * @return whether the replacement happened
     */
    public boolean replace(String key, T expected, T value) {
        return cache.asMap().replace(key, expected, value);
    }

    public String add(String key, T value) {
        if (key != null && !key.isBlank() && value != null) {
            cache.put(key, value);
            return key;
        }
        return null;  // Retornar null para indicar que no se agregó nada
    }

}
