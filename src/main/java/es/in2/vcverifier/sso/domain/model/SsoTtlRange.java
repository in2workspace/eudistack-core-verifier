package es.in2.vcverifier.sso.domain.model;

import java.time.Duration;

/**
 * ADR-106 — límites y valores por defecto canónicos de TTL para sesiones SSO.
 * Punto único de definición (DRY): todo código que valide o genere TTLs
 * debe referenciar estas constantes en lugar de literales dispersos.
 */
public final class SsoTtlRange {

    /** Mínimo TTL absoluto: 5 minutos (seguridad mínima operativa). */
    public static final Duration MIN_ABSOLUTE = Duration.ofMinutes(5);

    /** Máximo TTL absoluto: 24 horas (límite de cumplimiento GDPR/eIDAS). */
    public static final Duration MAX_ABSOLUTE = Duration.ofHours(24);

    /** Mínimo TTL idle: 1 minuto. */
    public static final Duration MIN_IDLE = Duration.ofMinutes(1);

    /**
     * Máximo TTL idle: 8 horas (jornada laboral completa; no puede exceder
     * MAX_ABSOLUTE, y SsoSessionTtl refuerza idle ≤ absolute).
     */
    public static final Duration MAX_IDLE = Duration.ofHours(8);

    /** TTL absoluto por defecto del sistema: jornada laboral completa. */
    public static final Duration DEFAULT_ABSOLUTE = Duration.ofHours(8);

    /** TTL idle por defecto del sistema. */
    public static final Duration DEFAULT_IDLE = Duration.ofMinutes(30);

    private SsoTtlRange() {}
}
