package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TenantSsoTtlPolicyTest {

    private final TenantSsoTtlPolicy policy = new TenantSsoTtlPolicy();

    // =========================================================
    // validate() — AC-01: valores dentro del rango permitido
    // =========================================================

    @Test
    void validate_returnsTrue_whenBothTtlsAreWithinRange() {
        assertThat(policy.validate(Duration.ofHours(8), Duration.ofMinutes(30))).isTrue();
    }

    // =========================================================
    // validate() — AC-02: rechazo por debajo del mínimo
    // =========================================================

    @Test
    void validate_returnsFalse_whenAbsoluteTtlBelowMinimum() {
        Duration belowMin = SsoTtlRange.MIN_ABSOLUTE.minusSeconds(1);
        assertThat(policy.validate(belowMin, SsoTtlRange.DEFAULT_IDLE)).isFalse();
    }

    @Test
    void validate_returnsFalse_whenIdleTtlBelowMinimum() {
        Duration belowMin = SsoTtlRange.MIN_IDLE.minusSeconds(1);
        assertThat(policy.validate(SsoTtlRange.DEFAULT_ABSOLUTE, belowMin)).isFalse();
    }

    // =========================================================
    // validate() — AC-03: rechazo por encima del máximo
    // =========================================================

    @Test
    void validate_returnsFalse_whenAbsoluteTtlExceedsMaximum() {
        Duration aboveMax = SsoTtlRange.MAX_ABSOLUTE.plusSeconds(1);
        assertThat(policy.validate(aboveMax, SsoTtlRange.DEFAULT_IDLE)).isFalse();
    }

    @Test
    void validate_returnsFalse_whenIdleTtlExceedsMaximum() {
        Duration aboveMax = SsoTtlRange.MAX_IDLE.plusSeconds(1);
        assertThat(policy.validate(SsoTtlRange.DEFAULT_ABSOLUTE, aboveMax)).isFalse();
    }

    // =========================================================
    // validate() — EC-01: null lanza NullPointerException
    // =========================================================

    @Test
    void validate_throwsNullPointerException_whenAbsoluteIsNull() {
        assertThrows(NullPointerException.class,
                () -> policy.validate(null, SsoTtlRange.DEFAULT_IDLE));
    }

    // =========================================================
    // validate() — EC-03: null idle lanza NullPointerException
    // =========================================================

    @Test
    void validate_throwsNullPointerException_whenIdleIsNull() {
        assertThrows(NullPointerException.class,
                () -> policy.validate(SsoTtlRange.DEFAULT_ABSOLUTE, null));
    }

    // =========================================================
    // validate() — NFR-S-549-01: límites inclusivos aceptados
    // =========================================================

    @Test
    void validate_returnsTrue_atMinimumBoundary() {
        assertThat(policy.validate(SsoTtlRange.MIN_ABSOLUTE, SsoTtlRange.MIN_IDLE)).isTrue();
    }

    @Test
    void validate_returnsTrue_atMaximumBoundary() {
        assertThat(policy.validate(SsoTtlRange.MAX_ABSOLUTE, SsoTtlRange.MAX_IDLE)).isTrue();
    }

    // =========================================================
    // resolve() — ambos null → defaults del sistema
    // =========================================================

    @Test
    void resolve_returnsSystemDefaults_whenBothOverridesAreNull() {
        SsoSessionTtl result = policy.resolve(null, null);
        assertThat(result.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(result.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // =========================================================
    // resolve() — AC-01: overrides válidos aplicados
    // =========================================================

    @Test
    void resolve_usesOverrides_whenBothAreValid() {
        Duration customAbsolute = Duration.ofHours(4);
        Duration customIdle = Duration.ofMinutes(15);

        SsoSessionTtl result = policy.resolve(customAbsolute, customIdle);

        assertThat(result.absolute()).isEqualTo(customAbsolute);
        assertThat(result.idle()).isEqualTo(customIdle);
    }

    // =========================================================
    // resolve() — AC-02 / resolución por dimensión:
    // absolute inválido → default absolute; idle válido → override idle
    // =========================================================

    @Test
    void resolve_fallsBackAbsoluteToDefault_whenAbsoluteIsInvalid() {
        Duration invalidAbsolute = SsoTtlRange.MAX_ABSOLUTE.plusSeconds(1);
        Duration customIdle = Duration.ofMinutes(15);

        SsoSessionTtl result = policy.resolve(invalidAbsolute, customIdle);

        assertThat(result.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(result.idle()).isEqualTo(customIdle);
    }

    // =========================================================
    // resolve() — AC-03 / resolución por dimensión:
    // absolute válido → override absolute; idle inválido → default idle
    // =========================================================

    @Test
    void resolve_fallsBackIdleToDefault_whenIdleIsInvalid() {
        Duration customAbsolute = Duration.ofHours(4);
        Duration invalidIdle = SsoTtlRange.MAX_IDLE.plusSeconds(1);

        SsoSessionTtl result = policy.resolve(customAbsolute, invalidIdle);

        assertThat(result.absolute()).isEqualTo(customAbsolute);
        assertThat(result.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // =========================================================
    // resolve() — null absolute → default absolute; idle válido → override idle
    // =========================================================

    @Test
    void resolve_fallsBackAbsoluteToDefault_whenAbsoluteIsNull() {
        Duration customIdle = Duration.ofMinutes(15);

        SsoSessionTtl result = policy.resolve(null, customIdle);

        assertThat(result.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(result.idle()).isEqualTo(customIdle);
    }

    @Test
    void resolve_fallsBackIdleToDefault_whenIdleIsNull() {
        Duration customAbsolute = Duration.ofHours(4);

        SsoSessionTtl result = policy.resolve(customAbsolute, null);

        assertThat(result.absolute()).isEqualTo(customAbsolute);
        assertThat(result.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }
}
