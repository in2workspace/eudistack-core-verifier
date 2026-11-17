package es.in2.vcverifier.shared.infrastructure.audit;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RejectionThrottleTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-13T10:00:00Z"));
    private final RejectionThrottle throttle = new RejectionThrottle(clock);

    @Test
    void allow_sameKeyBeyondTheLimit_isRefused() {
        for (int i = 0; i < RejectionThrottle.MAX_PER_KEY; i++) {
            assertTrue(throttle.allow("dome|machine|invalid"));
        }

        assertFalse(throttle.allow("dome|machine|invalid"));
        assertTrue(throttle.allow("dome|other-machine|invalid"));
    }

    @Test
    void allow_nextWindow_startsAgain() {
        for (int i = 0; i <= RejectionThrottle.MAX_PER_KEY; i++) {
            throttle.allow("dome|machine|invalid");
        }
        clock.advance(RejectionThrottle.WINDOW.plusSeconds(1));

        assertTrue(throttle.allow("dome|machine|invalid"));
    }

    @Test
    void allow_tooManyDifferentKeys_stopsAtTheTotalCap() {
        int allowed = 0;
        for (int i = 0; i < RejectionThrottle.MAX_IN_TOTAL + 50; i++) {
            if (throttle.allow("key-" + i)) {
                allowed++;
            }
        }

        org.junit.jupiter.api.Assertions.assertEquals(RejectionThrottle.MAX_IN_TOTAL, allowed);
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
