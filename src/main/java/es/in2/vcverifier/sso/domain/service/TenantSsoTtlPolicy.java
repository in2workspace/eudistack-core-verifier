package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Objects;

/**
 * Política de dominio para resolución y validación
 * de TTLs SSO configurables por tenant.
 *
 * Reglas:
 *
 * - validate(): rango cerrado inclusivo.
 * - resolve():
 *      * override válido -> usar override
 *      * override nulo -> default
 *      * override inválido -> default + log
 */
public class TenantSsoTtlPolicy {

    private static final Logger log =
            LoggerFactory.getLogger(TenantSsoTtlPolicy.class);

    /**
     * Valida que ambos TTLs estén dentro
     * de los límites permitidos.
     *
     * Rango cerrado inclusivo.
     */
    public boolean validate(
            Duration absolute,
            Duration idle
    ) {

        Objects.requireNonNull(absolute, "absolute cannot be null");
        Objects.requireNonNull(idle, "idle cannot be null");

        boolean absoluteValid =
                absolute.compareTo(SsoTtlRange.MIN_ABSOLUTE) >= 0
                        && absolute.compareTo(SsoTtlRange.MAX_ABSOLUTE) <= 0;

        boolean idleValid =
                idle.compareTo(SsoTtlRange.MIN_IDLE) >= 0
                        && idle.compareTo(SsoTtlRange.MAX_IDLE) <= 0;

        boolean valid = absoluteValid && idleValid;

        if (!valid) {
            log.warn(
                    "Rejected tenant SSO TTL configuration. absolute={} idle={} " +
                            "allowedAbsolute=[{}, {}] allowedIdle=[{}, {}]",
                    absolute,
                    idle,
                    SsoTtlRange.MIN_ABSOLUTE,
                    SsoTtlRange.MAX_ABSOLUTE,
                    SsoTtlRange.MIN_IDLE,
                    SsoTtlRange.MAX_IDLE
            );
        }

        return valid;
    }

    /**
     * Resuelve la configuración efectiva.
     *
     * Override por dimensión:
     *
     * - absolute válido -> override
     * - absolute inválido/null -> default absolute
     *
     * - idle válido -> override
     * - idle inválido/null -> default idle
     */
    public SsoSessionTtl resolve(
            Duration overrideAbsolute,
            Duration overrideIdle
    ) {

        Duration resolvedAbsolute =
                resolveAbsolute(overrideAbsolute);

        Duration resolvedIdle =
                resolveIdle(overrideIdle);

        return SsoSessionTtl.of(
                resolvedAbsolute,
                resolvedIdle
        );
    }

    private Duration resolveAbsolute(Duration overrideAbsolute) {

        if (overrideAbsolute == null) {
            return SsoTtlRange.DEFAULT_ABSOLUTE;
        }

        boolean valid =
                overrideAbsolute.compareTo(SsoTtlRange.MIN_ABSOLUTE) >= 0
                        && overrideAbsolute.compareTo(SsoTtlRange.MAX_ABSOLUTE) <= 0;

        if (!valid) {

            log.warn(
                    "Invalid tenant absolute TTL {}. Falling back to default {}",
                    overrideAbsolute,
                    SsoTtlRange.DEFAULT_ABSOLUTE
            );

            return SsoTtlRange.DEFAULT_ABSOLUTE;
        }

        return overrideAbsolute;
    }

    private Duration resolveIdle(Duration overrideIdle) {

        if (overrideIdle == null) {
            return SsoTtlRange.DEFAULT_IDLE;
        }

        boolean valid =
                overrideIdle.compareTo(SsoTtlRange.MIN_IDLE) >= 0
                        && overrideIdle.compareTo(SsoTtlRange.MAX_IDLE) <= 0;

        if (!valid) {

            log.warn(
                    "Invalid tenant idle TTL {}. Falling back to default {}",
                    overrideIdle,
                    SsoTtlRange.DEFAULT_IDLE
            );

            return SsoTtlRange.DEFAULT_IDLE;
        }

        return overrideIdle;
    }
}