package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC-01..03  validate() rango cerrado inclusivo y rechazo fuera de rango.
 * EC-01      null tratado como inválido en validate() y resolve().
 * NFR-S-549-01  resolve() nunca lanza excepción; siempre devuelve SsoSessionTtl no nulo.
 *
 * Nota: la condición idle &gt; absolute (EC-03) es formalmente inalcanzable cuando ambas
 * dimensiones están en rango, dado que MAX_IDLE (PT1H) ≤ MIN_ABSOLUTE (PT1H).
 * El código defensivo permanece en TenantSsoTtlPolicy como invariante de seguridad.
 */
class TenantSsoTtlPolicyTest {

    private final TenantSsoTtlPolicy policy = new TenantSsoTtlPolicy();

    // ─── validate() ──────────────────────────────────────────────────────────

    // AC-01: par válido dentro del rango
    @Test
    void validate_shouldReturnTrue_whenBothDimensionsAreWithinRange() {
        assertTrue(policy.validate(Duration.ofHours(8), Duration.ofMinutes(30)));
    }

    // AC-02: valores exactamente en el límite inferior (rango cerrado inclusivo)
    @Test
    void validate_shouldReturnTrue_whenBothDimensionsAreAtMinimumBoundary() {
        assertTrue(policy.validate(SsoTtlRange.MIN_ABSOLUTE, SsoTtlRange.MIN_IDLE));
    }

    // AC-02: valores exactamente en el límite superior (rango cerrado inclusivo)
    @Test
    void validate_shouldReturnTrue_whenBothDimensionsAreAtMaximumBoundary() {
        assertTrue(policy.validate(SsoTtlRange.MAX_ABSOLUTE, SsoTtlRange.MAX_IDLE));
    }

    // AC-03: absolute por debajo del mínimo (59 min < MIN_ABSOLUTE = 1h)
    @Test
    void validate_shouldReturnFalse_whenAbsoluteBelowMinimum() {
        assertFalse(policy.validate(Duration.ofMinutes(59), Duration.ofMinutes(30)));
    }

    // AC-03: absolute por encima del máximo
    @Test
    void validate_shouldReturnFalse_whenAbsoluteAboveMaximum() {
        assertFalse(policy.validate(Duration.ofHours(25), Duration.ofMinutes(30)));
    }

    // AC-03: idle por debajo del mínimo (4 min < MIN_IDLE = 5 min)
    @Test
    void validate_shouldReturnFalse_whenIdleBelowMinimum() {
        assertFalse(policy.validate(Duration.ofHours(8), Duration.ofMinutes(4)));
    }

    // AC-03: idle por encima del máximo (90 min > MAX_IDLE = 60 min)
    @Test
    void validate_shouldReturnFalse_whenIdleAboveMaximum() {
        assertFalse(policy.validate(Duration.ofHours(10), Duration.ofMinutes(90)));
    }

    // EC-01: absolute nulo tratado como inválido
    @Test
    void validate_shouldReturnFalse_whenAbsoluteIsNull() {
        assertFalse(policy.validate(null, Duration.ofMinutes(30)));
    }

    // EC-01: idle nulo tratado como inválido
    @Test
    void validate_shouldReturnFalse_whenIdleIsNull() {
        assertFalse(policy.validate(Duration.ofHours(8), null));
    }

    // N5: límite inferior de absolute evaluado individualmente
    @Test
    void validate_shouldReturnTrue_whenAbsoluteIsAtMinimumBoundaryAndIdleIsMiddle() {
        assertTrue(policy.validate(SsoTtlRange.MIN_ABSOLUTE, Duration.ofMinutes(30)));
    }

    // N5: límite superior de absolute evaluado individualmente
    @Test
    void validate_shouldReturnTrue_whenAbsoluteIsAtMaximumBoundaryAndIdleIsMiddle() {
        assertTrue(policy.validate(SsoTtlRange.MAX_ABSOLUTE, Duration.ofMinutes(30)));
    }

    // N5: límite inferior de idle evaluado individualmente
    @Test
    void validate_shouldReturnTrue_whenIdleIsAtMinimumBoundaryAndAbsoluteIsMiddle() {
        assertTrue(policy.validate(Duration.ofHours(8), SsoTtlRange.MIN_IDLE));
    }

    // N5: límite superior de idle evaluado individualmente
    @Test
    void validate_shouldReturnTrue_whenIdleIsAtMaximumBoundaryAndAbsoluteIsMiddle() {
        assertTrue(policy.validate(Duration.ofHours(8), SsoTtlRange.MAX_IDLE));
    }

    // ─── resolve() ───────────────────────────────────────────────────────────

    // AC-01: overrides válidos en ambas dimensiones → se usan directamente
    @Test
    void resolve_shouldUseValidOverrides_whenBothDimensionsAreInRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofHours(4), Duration.ofMinutes(15));

        assertEquals(Duration.ofHours(4), ttl.absolute());
        assertEquals(Duration.ofMinutes(15), ttl.idle());
    }

    // AC-03: absolute fuera de rango (45 min < MIN_ABSOLUTE = 1h) → DEFAULT_ABSOLUTE; idle válido se respeta
    @Test
    void resolve_shouldFallBackToDefaultAbsolute_whenAbsoluteIsOutOfRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofMinutes(45), Duration.ofMinutes(15));

        assertEquals(SsoTtlRange.DEFAULT_ABSOLUTE, ttl.absolute());
        assertEquals(Duration.ofMinutes(15), ttl.idle());
    }

    // AC-03: idle fuera de rango (4 min < MIN_IDLE = 5 min) → DEFAULT_IDLE; absolute válido se respeta
    @Test
    void resolve_shouldFallBackToDefaultIdle_whenIdleIsOutOfRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofHours(4), Duration.ofMinutes(4));

        assertEquals(Duration.ofHours(4), ttl.absolute());
        assertEquals(SsoTtlRange.DEFAULT_IDLE, ttl.idle());
    }

    // EC-01: ambos nulos → se aplican ambos defaults del sistema
    @Test
    void resolve_shouldReturnSystemDefaults_whenBothOverridesAreNull() {
        SsoSessionTtl ttl = policy.resolve(null, null);

        assertEquals(SsoTtlRange.DEFAULT_ABSOLUTE, ttl.absolute());
        assertEquals(SsoTtlRange.DEFAULT_IDLE, ttl.idle());
    }

    // NFR-S-549-01: resolve() nunca lanza, siempre devuelve un valor no nulo
    @Test
    void resolve_shouldNeverThrow_andAlwaysReturnNonNull() {
        assertDoesNotThrow(() -> {
            SsoSessionTtl ttl = policy.resolve(null, null);
            assertNotNull(ttl);
        });
    }
}
