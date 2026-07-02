package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC-04  isValid() devuelve false cuando el TTL absoluto ha vencido (now >= expiresAt).
 * AC-05  isValid() devuelve false cuando el idle TTL ha sido superado (now − lastUsedAt > idleTtl).
 * EC-02  Parámetros null lanzan NullPointerException.
 * Verifica también el caso positivo y los valores límite exactos.
 */
class SsoSessionIsValidTest {

    private static final Instant BASE = Instant.parse("2026-01-15T10:00:00Z");

    private static SsoSession session(Instant established, Instant expires, Instant lastUsed) {
        return SsoSession.reconstitute(
                SsoSessionId.of("test-session-id-1"),
                "tenant-a",
                "holder-hash-abc",
                established,
                expires,
                lastUsed,
                SsoSessionState.ACTIVE
        );
    }

    // ─── Caso positivo ────────────────────────────────────────────────────────

    @Test
    void isValid_shouldReturnTrue_whenNotExpiredAndIdleWithinTtl() {
        SsoSession s = session(
                BASE.minus(Duration.ofMinutes(30)),   // established 30 min atrás
                BASE.plus(Duration.ofHours(7).plusMinutes(30)), // expira en 7h30
                BASE.minus(Duration.ofMinutes(5))     // último uso: 5 min atrás
        );

        assertTrue(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // ─── AC-04: TTL absoluto vencido ─────────────────────────────────────────

    @Test
    void isValid_shouldReturnFalse_whenAbsoluteTtlHasExpired() {
        SsoSession s = session(
                BASE.minus(Duration.ofHours(9)),      // established hace 9h
                BASE.minus(Duration.ofSeconds(1)),    // expiró 1 segundo antes de now
                BASE.minus(Duration.ofMinutes(1))
        );

        assertFalse(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // AC-04: límite exacto — now == expiresAt → isBefore es estricto, por lo tanto inválido
    @Test
    void isValid_shouldReturnFalse_whenNowEqualsExpiresAt() {
        SsoSession s = session(
                BASE.minus(Duration.ofHours(8)),
                BASE,                                 // expiresAt == now
                BASE.minus(Duration.ofMinutes(1))
        );

        assertFalse(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // ─── AC-05: idle TTL excedido ─────────────────────────────────────────────

    @Test
    void isValid_shouldReturnFalse_whenIdleTtlExceeded() {
        SsoSession s = session(
                BASE.minus(Duration.ofHours(1)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(31))    // 31 min de inactividad, idleTtl=30 min
        );

        assertFalse(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // AC-05: límite exacto — Duration.between(lastUsedAt, now) == idleTtl → compareTo = 0 ≤ 0 → válido
    @Test
    void isValid_shouldReturnTrue_whenIdleEqualsTtlExactBoundary() {
        SsoSession s = session(
                BASE.minus(Duration.ofHours(1)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(30))    // exactamente 30 min de inactividad, idleTtl=30 min
        );

        assertTrue(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // ─── Ambas condiciones fallidas ───────────────────────────────────────────

    @Test
    void isValid_shouldReturnFalse_whenBothAbsoluteAndIdleAreInvalid() {
        SsoSession s = session(
                BASE.minus(Duration.ofHours(10)),
                BASE.minus(Duration.ofMinutes(5)),    // expiró 5 min antes
                BASE.minus(Duration.ofHours(2))       // 2h de inactividad, idle=30min
        );

        assertFalse(s.isValid(BASE, Duration.ofMinutes(30)));
    }

    // ─── EC-02: parámetros null ───────────────────────────────────────────────

    @Test
    void isValid_shouldThrowNullPointerException_whenNowIsNull() {
        SsoSession s = session(
                BASE.minus(Duration.ofMinutes(30)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(5))
        );

        assertThrows(NullPointerException.class,
                () -> s.isValid(null, Duration.ofMinutes(30)));
    }

    @Test
    void isValid_shouldThrowNullPointerException_whenIdleTtlIsNull() {
        SsoSession s = session(
                BASE.minus(Duration.ofMinutes(30)),
                BASE.plus(Duration.ofHours(7)),
                BASE.minus(Duration.ofMinutes(5))
        );

        assertThrows(NullPointerException.class,
                () -> s.isValid(BASE, null));
    }
}
