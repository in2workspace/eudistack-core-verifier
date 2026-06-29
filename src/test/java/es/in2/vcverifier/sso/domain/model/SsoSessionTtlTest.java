package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SsoSessionTtlTest {

    // =========================================================
    // SsoTtlRange — constantes del sistema (ADR-106)
    // =========================================================

    @Test
    void SsoTtlRange_defaultAbsolute_isEightHours() {
        assertThat(SsoTtlRange.DEFAULT_ABSOLUTE).isEqualTo(Duration.ofHours(8));
    }

    @Test
    void SsoTtlRange_defaultIdle_isThirtyMinutes() {
        assertThat(SsoTtlRange.DEFAULT_IDLE).isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void SsoTtlRange_minAbsolute_isFiveMinutes() {
        assertThat(SsoTtlRange.MIN_ABSOLUTE).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void SsoTtlRange_maxAbsolute_isTwentyFourHours() {
        assertThat(SsoTtlRange.MAX_ABSOLUTE).isEqualTo(Duration.ofHours(24));
    }

    @Test
    void SsoTtlRange_minIdle_isOneMinute() {
        assertThat(SsoTtlRange.MIN_IDLE).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void SsoTtlRange_maxIdle_isEightHours() {
        assertThat(SsoTtlRange.MAX_IDLE).isEqualTo(Duration.ofHours(8));
    }

    // =========================================================
    // SsoSessionTtl.of() — factory principal
    // =========================================================

    @Test
    void of_createsInstance_withCorrectAccessors() {
        Duration absolute = Duration.ofHours(4);
        Duration idle = Duration.ofMinutes(20);

        SsoSessionTtl ttl = SsoSessionTtl.of(absolute, idle);

        assertThat(ttl.absolute()).isEqualTo(absolute);
        assertThat(ttl.idle()).isEqualTo(idle);
    }

    @Test
    void of_acceptsMinimumBoundaryValues() {
        SsoSessionTtl ttl = SsoSessionTtl.of(SsoTtlRange.MIN_ABSOLUTE, SsoTtlRange.MIN_IDLE);

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.MIN_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.MIN_IDLE);
    }

    @Test
    void of_acceptsMaximumBoundaryValues() {
        SsoSessionTtl ttl = SsoSessionTtl.of(SsoTtlRange.MAX_ABSOLUTE, SsoTtlRange.MAX_IDLE);

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.MAX_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.MAX_IDLE);
    }

    // =========================================================
    // SsoSessionTtl.of() — validaciones de rango
    // =========================================================

    @Test
    void of_throwsIllegalArgument_whenAbsoluteBelowMinimum() {
        Duration belowMin = SsoTtlRange.MIN_ABSOLUTE.minusSeconds(1);

        assertThatThrownBy(() -> SsoSessionTtl.of(belowMin, SsoTtlRange.DEFAULT_IDLE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("minimum");
    }

    @Test
    void of_throwsIllegalArgument_whenAbsoluteExceedsMaximum() {
        Duration aboveMax = SsoTtlRange.MAX_ABSOLUTE.plusSeconds(1);

        assertThatThrownBy(() -> SsoSessionTtl.of(aboveMax, SsoTtlRange.DEFAULT_IDLE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum");
    }

    @Test
    void of_throwsIllegalArgument_whenIdleBelowMinimum() {
        Duration belowMin = SsoTtlRange.MIN_IDLE.minusSeconds(1);

        assertThatThrownBy(() -> SsoSessionTtl.of(SsoTtlRange.DEFAULT_ABSOLUTE, belowMin))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("minimum");
    }

    @Test
    void of_throwsIllegalArgument_whenIdleExceedsMaximum() {
        Duration aboveMax = SsoTtlRange.MAX_IDLE.plusSeconds(1);

        assertThatThrownBy(() -> SsoSessionTtl.of(SsoTtlRange.DEFAULT_ABSOLUTE, aboveMax))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum");
    }

    @Test
    void of_throwsNullPointerException_whenAbsoluteIsNull() {
        assertThatThrownBy(() -> SsoSessionTtl.of(null, SsoTtlRange.DEFAULT_IDLE))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void of_throwsNullPointerException_whenIdleIsNull() {
        assertThatThrownBy(() -> SsoSessionTtl.of(SsoTtlRange.DEFAULT_ABSOLUTE, null))
                .isInstanceOf(NullPointerException.class);
    }

    // =========================================================
    // SsoSessionTtl.systemDefault()
    // =========================================================

    @Test
    void systemDefault_returnsDefaultAbsoluteAndIdle() {
        SsoSessionTtl ttl = SsoSessionTtl.systemDefault();

        assertThat(ttl.absolute()).isEqualTo(SsoTtlRange.DEFAULT_ABSOLUTE);
        assertThat(ttl.idle()).isEqualTo(SsoTtlRange.DEFAULT_IDLE);
    }

    // =========================================================
    // equals() y hashCode()
    // =========================================================

    @Test
    void equals_returnsTrue_forSameValues() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30));

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void equals_returnsFalse_whenAbsoluteDiffers() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(4), Duration.ofMinutes(30));

        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void equals_returnsFalse_whenIdleDiffers() {
        SsoSessionTtl a = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30));
        SsoSessionTtl b = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(15));

        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void equals_returnsTrue_forSameInstance() {
        SsoSessionTtl ttl = SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30));

        assertThat(ttl).isEqualTo(ttl);
    }
}
