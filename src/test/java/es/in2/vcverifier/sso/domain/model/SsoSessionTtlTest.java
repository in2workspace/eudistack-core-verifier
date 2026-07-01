package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pruebas para el value object SsoSessionTtl y las constantes ADR-106 de SsoTtlRange.
 * Verifica: factory of(), systemDefault(), validaciones en construcción, equals/hashCode.
 */
class SsoSessionTtlTest {

    // ─── systemDefault() ─────────────────────────────────────────────────────

    @Test
    void systemDefault_shouldReturnDefaultAbsoluteAndIdle() {
        SsoSessionTtl ttl = SsoSessionTtl.systemDefault();

        assertEquals(SsoTtlRange.DEFAULT_ABSOLUTE, ttl.absolute());
        assertEquals(SsoTtlRange.DEFAULT_IDLE, ttl.idle());
    }

    // ─── of() — construcción válida ──────────────────────────────────────────

    @Test
    void of_shouldStoreProvidedValues_whenInputsAreValid() {
        Duration abs  = Duration.ofHours(4);
        Duration idle = Duration.ofMinutes(20);

        SsoSessionTtl ttl = SsoSessionTtl.of(abs, idle);

        assertEquals(abs,  ttl.absolute());
        assertEquals(idle, ttl.idle());
    }

    // ─── of() — validaciones en construcción ─────────────────────────────────

    @Test
    void of_shouldThrowNullPointerException_whenAbsoluteIsNull() {
        assertThrows(NullPointerException.class,
                () -> SsoSessionTtl.of(null, Duration.ofMinutes(30)));
    }

    @Test
    void of_shouldThrowNullPointerException_whenIdleIsNull() {
        assertThrows(NullPointerException.class,
                () -> SsoSessionTtl.of(Duration.ofHours(8), null));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenAbsoluteBelowMinimum() {
        // MIN_ABSOLUTE = 1h; 59 min está fuera de rango
        assertThrows(IllegalArgumentException.class,
                () -> SsoSessionTtl.of(Duration.ofMinutes(59), Duration.ofMinutes(30)));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenAbsoluteAboveMaximum() {
        // MAX_ABSOLUTE = 24h; 25h está fuera de rango
        assertThrows(IllegalArgumentException.class,
                () -> SsoSessionTtl.of(Duration.ofHours(25), Duration.ofHours(1)));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenIdleBelowMinimum() {
        // MIN_IDLE = 5 min; 4 min está fuera de rango
        assertThrows(IllegalArgumentException.class,
                () -> SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(4)));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenIdleAboveMaximum() {
        // MAX_IDLE = 60 min; 90 min está fuera de rango
        assertThrows(IllegalArgumentException.class,
                () -> SsoSessionTtl.of(Duration.ofHours(2), Duration.ofMinutes(90)));
    }

    // ─── SsoTtlRange — constantes ADR-106 ────────────────────────────────────

    @Test
    void ssoTtlRange_constants_shouldMatchAdr106CanonicalValues() {
        assertEquals(Duration.ofHours(1),    SsoTtlRange.MIN_ABSOLUTE);
        assertEquals(Duration.ofHours(24),   SsoTtlRange.MAX_ABSOLUTE);
        assertEquals(Duration.ofMinutes(5),  SsoTtlRange.MIN_IDLE);
        assertEquals(Duration.ofMinutes(60), SsoTtlRange.MAX_IDLE);
        assertEquals(Duration.ofHours(8),    SsoTtlRange.DEFAULT_ABSOLUTE);
        assertEquals(Duration.ofMinutes(30), SsoTtlRange.DEFAULT_IDLE);
    }

    @Test
    void ssoTtlRange_defaultsShouldSatisfyTheirOwnConstraints() {
        // DEFAULT_ABSOLUTE ∈ [MIN_ABSOLUTE, MAX_ABSOLUTE]
        assertTrue(SsoTtlRange.DEFAULT_ABSOLUTE.compareTo(SsoTtlRange.MIN_ABSOLUTE) >= 0);
        assertTrue(SsoTtlRange.DEFAULT_ABSOLUTE.compareTo(SsoTtlRange.MAX_ABSOLUTE) <= 0);

        // DEFAULT_IDLE ∈ [MIN_IDLE, MAX_IDLE]
        assertTrue(SsoTtlRange.DEFAULT_IDLE.compareTo(SsoTtlRange.MIN_IDLE) >= 0);
        assertTrue(SsoTtlRange.DEFAULT_IDLE.compareTo(SsoTtlRange.MAX_IDLE) <= 0);

        // DEFAULT_IDLE ≤ DEFAULT_ABSOLUTE (invariante idle ≤ absolute)
        assertTrue(SsoTtlRange.DEFAULT_IDLE.compareTo(SsoTtlRange.DEFAULT_ABSOLUTE) <= 0);
    }

    // ─── equals / hashCode ───────────────────────────────────────────────────

    @Test
    void equals_shouldReturnTrue_forObjectsWithSameValues() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(20));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(20));

        assertEquals(a, b);
        assertEquals(b, a);
    }

    @Test
    void equals_shouldReturnFalse_forObjectsWithDifferentValues() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(20));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(6), Duration.ofMinutes(20));

        assertNotEquals(a, b);
    }

    @Test
    void hashCode_shouldBeConsistentWithEquals() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(20));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(20));

        assertEquals(a.hashCode(), b.hashCode());
    }
}
