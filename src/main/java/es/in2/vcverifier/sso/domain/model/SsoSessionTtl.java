package es.in2.vcverifier.sso.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Value Object inmutable que representa
 * la configuración TTL de una sesión SSO.
 *
 * Contiene:
 * - Absolute TTL
 * - Idle TTL
 */
public final class SsoSessionTtl {

    private final Duration absolute;
    private final Duration idle;

    private SsoSessionTtl(
            Duration absolute,
            Duration idle
    ) {

        validateAbsolute(absolute);
        validateIdle(idle);

        this.absolute = absolute;
        this.idle = idle;
    }

    /**
     * Factory principal.
     */
    public static SsoSessionTtl of(
            Duration absolute,
            Duration idle
    ) {
        return new SsoSessionTtl(absolute, idle);
    }

    /**
     * Configuración por defecto del sistema.
     */
    public static SsoSessionTtl systemDefault() {
        return new SsoSessionTtl(
                SsoTtlRange.DEFAULT_ABSOLUTE,
                SsoTtlRange.DEFAULT_IDLE
        );
    }

    public Duration absolute() {
        return absolute;
    }

    public Duration idle() {
        return idle;
    }

    private static void validateAbsolute(Duration absolute) {

        Objects.requireNonNull(
                absolute,
                "absolute TTL cannot be null"
        );

        if (absolute.compareTo(SsoTtlRange.MIN_ABSOLUTE) < 0) {
            throw new IllegalArgumentException(
                    "absolute TTL below minimum allowed value"
            );
        }

        if (absolute.compareTo(SsoTtlRange.MAX_ABSOLUTE) > 0) {
            throw new IllegalArgumentException(
                    "absolute TTL exceeds maximum allowed value"
            );
        }
    }

    private static void validateIdle(Duration idle) {

        Objects.requireNonNull(
                idle,
                "idle TTL cannot be null"
        );

        if (idle.compareTo(SsoTtlRange.MIN_IDLE) < 0) {
            throw new IllegalArgumentException(
                    "idle TTL below minimum allowed value"
            );
        }

        if (idle.compareTo(SsoTtlRange.MAX_IDLE) > 0) {
            throw new IllegalArgumentException(
                    "idle TTL exceeds maximum allowed value"
            );
        }
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }

        if (!(o instanceof SsoSessionTtl that)) {
            return false;
        }

        return absolute.equals(that.absolute)
                && idle.equals(that.idle);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                absolute,
                idle
        );
    }

    @Override
    public String toString() {
        return "SsoSessionTtl{" +
                "absolute=" + absolute +
                ", idle=" + idle +
                '}';
    }

}