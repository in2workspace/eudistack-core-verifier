package es.in2.vcverifier.sso.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Value object inmutable que encapsula el par (absolute, idle) de TTL para una sesión SSO.
 * Validado en construcción contra los límites de ADR-106 ({@link SsoTtlRange}).
 */
public final class SsoSessionTtl {

    private final Duration absolute;
    private final Duration idle;

    private SsoSessionTtl(Duration absolute, Duration idle) {
        Objects.requireNonNull(absolute, "absolute TTL must not be null");
        Objects.requireNonNull(idle,     "idle TTL must not be null");

        if (absolute.compareTo(SsoTtlRange.MIN_ABSOLUTE) < 0
                || absolute.compareTo(SsoTtlRange.MAX_ABSOLUTE) > 0) {
            throw new IllegalArgumentException(
                    "absolute TTL must be between %s and %s, got %s"
                            .formatted(SsoTtlRange.MIN_ABSOLUTE, SsoTtlRange.MAX_ABSOLUTE, absolute));
        }

        if (idle.compareTo(SsoTtlRange.MIN_IDLE) < 0
                || idle.compareTo(SsoTtlRange.MAX_IDLE) > 0) {
            throw new IllegalArgumentException(
                    "idle TTL must be between %s and %s, got %s"
                            .formatted(SsoTtlRange.MIN_IDLE, SsoTtlRange.MAX_IDLE, idle));
        }

        if (idle.compareTo(absolute) > 0) {
            throw new IllegalArgumentException(
                    "idle TTL (%s) must not exceed absolute TTL (%s)".formatted(idle, absolute));
        }

        this.absolute = absolute;
        this.idle     = idle;
    }

    /** Crea un TTL personalizado validado contra los límites de ADR-106. */
    public static SsoSessionTtl of(Duration absolute, Duration idle) {
        return new SsoSessionTtl(absolute, idle);
    }

    /** Devuelve el TTL por defecto del sistema: 8 h absolute / 30 min idle. */
    public static SsoSessionTtl systemDefault() {
        return new SsoSessionTtl(SsoTtlRange.DEFAULT_ABSOLUTE, SsoTtlRange.DEFAULT_IDLE);
    }

    public Duration absolute() {
        return absolute;
    }

    public Duration idle() {
        return idle;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SsoSessionTtl that)) return false;
        return Objects.equals(absolute, that.absolute)
                && Objects.equals(idle, that.idle);
    }

    @Override
    public int hashCode() {
        return Objects.hash(absolute, idle);
    }

    @Override
    public String toString() {
        return "SsoSessionTtl{absolute=" + absolute + ", idle=" + idle + "}";
    }
}
