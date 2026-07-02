package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

/**
 * Servicio de dominio que valida y resuelve la configuración de TTL de sesiones SSO
 * aplicando los rangos canónicos de ADR-106 ({@link SsoTtlRange}).
 *
 * No depende de infraestructura ni frameworks Spring.
 */
@Slf4j
public final class TenantSsoTtlPolicy {

    /**
     * Valida que el par (absolute, idle) cumpla los rangos cerrados inclusivos de ADR-106
     * y el invariante {@code idle ≤ absolute}. Registra en log cada dimensión rechazada.
     *
     * @return {@code true} si el par es completamente válido
     */
    public boolean validate(Duration absolute, Duration idle) {

        boolean absoluteOk = isAbsoluteInRange(absolute);
        boolean idleOk     = isIdleInRange(idle);

        if (!absoluteOk) {
            log.warn("sso_ttl_rejected dimension=absolute value={} range=[{}, {}]",
                    absolute, SsoTtlRange.MIN_ABSOLUTE, SsoTtlRange.MAX_ABSOLUTE);
        }

        if (!idleOk) {
            log.warn("sso_ttl_rejected dimension=idle value={} range=[{}, {}]",
                    idle, SsoTtlRange.MIN_IDLE, SsoTtlRange.MAX_IDLE);
        }

        if (absoluteOk && idleOk && idle.compareTo(absolute) > 0) {
            log.warn("sso_ttl_rejected constraint=idle_exceeds_absolute idle={} absolute={}",
                    idle, absolute);
            return false;
        }

        return absoluteOk && idleOk;
    }

    /**
     * Resuelve el TTL efectivo por dimensión: usa el override si es válido para esa
     * dimensión según los rangos de ADR-106; si no, aplica el valor por defecto del sistema.
     * <p>
     * Tras la resolución por dimensión, garantiza {@code idle ≤ absolute} capando idle
     * cuando la combinación resultante viola el invariante (ej. overrideAbsolute < DEFAULT_IDLE).
     */
    public SsoSessionTtl resolve(Duration overrideAbsolute, Duration overrideIdle) {

        Duration absolute = isAbsoluteInRange(overrideAbsolute)
                ? overrideAbsolute
                : SsoTtlRange.DEFAULT_ABSOLUTE;

        Duration idle = isIdleInRange(overrideIdle)
                ? overrideIdle
                : SsoTtlRange.DEFAULT_IDLE;

        if (idle.compareTo(absolute) > 0) {
            log.debug("sso_ttl_resolve idle_capped_to_absolute idle={} absolute={}", idle, absolute);
            idle = absolute;
        }

        return SsoSessionTtl.of(absolute, idle);
    }

    // ─── helpers de rango (cerrado inclusivo) ───────────────────────────────────

    private static boolean isAbsoluteInRange(Duration d) {
        return d != null
                && d.compareTo(SsoTtlRange.MIN_ABSOLUTE) >= 0
                && d.compareTo(SsoTtlRange.MAX_ABSOLUTE) <= 0;
    }

    private static boolean isIdleInRange(Duration d) {
        return d != null
                && d.compareTo(SsoTtlRange.MIN_IDLE) >= 0
                && d.compareTo(SsoTtlRange.MAX_IDLE) <= 0;
    }
}
