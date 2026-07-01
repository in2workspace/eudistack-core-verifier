package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC-01..03  validate() rango cerrado inclusivo y rechazo fuera de rango.
 * EC-01      null tratado como inválido en validate() y resolve().
 * EC-03      idle > absolute rechazado en validate().
 * NFR-S-549-01  resolve() nunca lanza excepción; siempre devuelve SsoSessionTtl no nulo.
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

    // AC-03: absolute por debajo del mínimo
    @Test
    void validate_shouldReturnFalse_whenAbsoluteBelowMinimum() {
        assertFalse(policy.validate(Duration.ofMinutes(4), Duration.ofMinutes(30)));
    }

    // AC-03: absolute por encima del máximo
    @Test
    void validate_shouldReturnFalse_whenAbsoluteAboveMaximum() {
        assertFalse(policy.validate(Duration.ofHours(25), Duration.ofMinutes(30)));
    }

    // AC-03: idle por debajo del mínimo (59 segundos < 1 minuto)
    @Test
    void validate_shouldReturnFalse_whenIdleBelowMinimum() {
        assertFalse(policy.validate(Duration.ofHours(8), Duration.ofSeconds(59)));
    }

    // AC-03: idle por encima del máximo (absolute = 10h, idle = 9h > MAX_IDLE = 8h)
    @Test
    void validate_shouldReturnFalse_whenIdleAboveMaximum() {
        assertFalse(policy.validate(Duration.ofHours(10), Duration.ofHours(9)));
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

    // EC-03: ambas dimensiones válidas pero idle > absolute
    @Test
    void validate_shouldReturnFalse_whenIdleExceedsAbsolute() {
        // absolute=1H (in range), idle=2H (in range), pero 2H > 1H
        assertFalse(policy.validate(Duration.ofHours(1), Duration.ofHours(2)));
    }

    // ─── resolve() ───────────────────────────────────────────────────────────

    // AC-01: overrides válidos en ambas dimensiones → se usan directamente
    @Test
    void resolve_shouldUseValidOverrides_whenBothDimensionsAreInRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofHours(4), Duration.ofMinutes(15));

        assertEquals(Duration.ofHours(4), ttl.absolute());
        assertEquals(Duration.ofMinutes(15), ttl.idle());
    }

    // AC-03: absolute fuera de rango → se aplica DEFAULT_ABSOLUTE; idle válido se respeta
    @Test
    void resolve_shouldFallBackToDefaultAbsolute_whenAbsoluteIsOutOfRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofMinutes(2), Duration.ofMinutes(15));

        assertEquals(SsoTtlRange.DEFAULT_ABSOLUTE, ttl.absolute());
        assertEquals(Duration.ofMinutes(15), ttl.idle());
    }

    // AC-03: idle fuera de rango → se aplica DEFAULT_IDLE; absolute válido se respeta
    @Test
    void resolve_shouldFallBackToDefaultIdle_whenIdleIsOutOfRange() {
        SsoSessionTtl ttl = policy.resolve(Duration.ofHours(4), Duration.ofSeconds(30));

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

    // idle-cap: overrideAbsolute válido pero pequeño, overrideIdle válido pero mayor que absolute
    // → idle debe caparse al valor de absolute (invariante idle ≤ absolute)
    @Test
    void resolve_shouldCapIdleToAbsolute_whenResolvedIdleExceedsResolvedAbsolute() {
        // absolute=PT10M (válido: MIN=5M ≤ 10M ≤ MAX=24H), idle=PT1H (válido en su rango),
        // pero 1H > 10M → idle debe caparse a PT10M
        Duration overrideAbsolute = Duration.ofMinutes(10);
        Duration overrideIdle = Duration.ofHours(1);

        SsoSessionTtl ttl = policy.resolve(overrideAbsolute, overrideIdle);

        assertEquals(overrideAbsolute, ttl.absolute());
        assertEquals(overrideAbsolute, ttl.idle(), "idle debe caparse al valor de absolute");
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
