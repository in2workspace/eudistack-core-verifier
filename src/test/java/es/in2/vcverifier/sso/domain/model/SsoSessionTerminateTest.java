package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * US-06 (Single Logout, AC-01/AC-02/EC-01): {@code SsoSession.terminate()}.
 * AC-01/AC-02: transición ACTIVE -&gt; TERMINATED, fija terminatedAt.
 * EC-01: idempotente semánticamente — no-op de dominio sobre un estado no-ACTIVE.
 */
class SsoSessionTerminateTest {

    private static final Instant BASE = Instant.parse("2026-01-15T10:00:00Z");

    private static SsoSession activeSession() {
        return SsoSession.reconstitute(
                SsoSessionId.of("test-session-id-1"),
                "tenant-a",
                "holder-hash-abc",
                BASE.minus(Duration.ofMinutes(30)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(5)),
                SsoSessionState.ACTIVE
        );
    }

    private static SsoSession sessionInState(SsoSessionState state) {
        return SsoSession.reconstitute(
                SsoSessionId.of("test-session-id-2"),
                "tenant-a",
                "holder-hash-abc",
                BASE.minus(Duration.ofMinutes(30)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(5)),
                state
        );
    }

    // ─── AC-01/AC-02: transición ACTIVE -> TERMINATED ─────────────────────────

    @Test
    void terminate_transitionsActiveToTerminated() {
        SsoSession session = activeSession();
        Instant terminatedAt = BASE.plus(Duration.ofMinutes(1));

        session.terminate(terminatedAt);

        assertEquals(SsoSessionState.TERMINATED, session.getState());
        assertEquals(terminatedAt, session.getTerminatedAt());
    }

    // ─── EC-01: no-op de dominio sobre estado no-ACTIVE ───────────────────────

    @Test
    void terminate_isNoopWhenAlreadyTerminated() {
        SsoSession session = sessionInState(SsoSessionState.TERMINATED);

        session.terminate(BASE.plus(Duration.ofMinutes(1)));

        assertEquals(SsoSessionState.TERMINATED, session.getState());
        assertNull(session.getTerminatedAt());
    }

    @Test
    void terminate_isNoopWhenSuperseded() {
        SsoSession session = sessionInState(SsoSessionState.SUPERSEDED);

        session.terminate(BASE.plus(Duration.ofMinutes(1)));

        assertEquals(SsoSessionState.SUPERSEDED, session.getState());
        assertNull(session.getTerminatedAt());
    }

    @Test
    void terminate_isNoopWhenExpired() {
        SsoSession session = sessionInState(SsoSessionState.EXPIRED);

        session.terminate(BASE.plus(Duration.ofMinutes(1)));

        assertEquals(SsoSessionState.EXPIRED, session.getState());
        assertNull(session.getTerminatedAt());
    }

    // ─── Guarda de construcción ────────────────────────────────────────────────

    @Test
    void terminate_shouldThrowNullPointerException_whenNowIsNull() {
        SsoSession session = activeSession();

        assertThrows(NullPointerException.class, () -> session.terminate(null));
    }
}
