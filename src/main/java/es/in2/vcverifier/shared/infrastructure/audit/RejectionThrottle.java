package es.in2.vcverifier.shared.infrastructure.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Keeps the trail of refused authentications from being flooded by whoever calls the token endpoint, which
 * needs no authentication to be refused. A refusal of the same client, tenant and reason leaves a few rows
 * per window, and all refusals together are capped, so a stream of garbage assertions cannot fill the audit
 * outbox, hold database connections or bury the real denials of a tenant.
 *
 * <p>State is in memory and per instance, which is enough for a limit that only has to bound the damage.
 */
@Component
public class RejectionThrottle {

    static final Duration WINDOW = Duration.ofMinutes(1);
    public static final int MAX_PER_KEY = 3;
    public static final int MAX_IN_TOTAL = 120;
    /** Beyond this many different keys in one window the table is dropped, so it cannot grow without bound. */
    static final int MAX_KEYS = 5_000;

    private final Clock clock;
    private final Map<String, Integer> perKey = new HashMap<>();
    private Instant windowStartedAt;
    private int total;

    @Autowired
    public RejectionThrottle() {
        this(Clock.systemUTC());
    }

    RejectionThrottle(Clock clock) {
        this.clock = clock;
        this.windowStartedAt = clock.instant();
    }

    /** Whether one more refusal with this key may be reported in the current window. */
    public synchronized boolean allow(String key) {
        Instant now = clock.instant();
        if (now.isAfter(windowStartedAt.plus(WINDOW))) {
            perKey.clear();
            total = 0;
            windowStartedAt = now;
        }
        if (total >= MAX_IN_TOTAL) {
            return false;
        }
        if (perKey.size() >= MAX_KEYS && !perKey.containsKey(key)) {
            return false;
        }
        int seen = perKey.merge(key, 1, Integer::sum);
        if (seen > MAX_PER_KEY) {
            return false;
        }
        total++;
        return true;
    }
}
