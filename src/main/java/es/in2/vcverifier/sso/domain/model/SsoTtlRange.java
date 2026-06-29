package es.in2.vcverifier.sso.domain.model;

import java.time.Duration;

/**
 * ADR-106
 *
 * Punto único de definición de límites y valores por defecto
 * para la configuración de TTL de sesiones SSO.
 *
 * Mantener todos los límites aquí evita duplicidades
 * y facilita futuras modificaciones.
 */
public final class SsoTtlRange {

    private SsoTtlRange() {
        // Utility class
    }

    /**
     * Valores por defecto del sistema.
     */
    public static final Duration DEFAULT_ABSOLUTE =
            Duration.ofHours(8);

    public static final Duration DEFAULT_IDLE =
            Duration.ofMinutes(30);

    /**
     * Límites permitidos para TTL absoluto.
     */
    public static final Duration MIN_ABSOLUTE =
            Duration.ofMinutes(5);

    public static final Duration MAX_ABSOLUTE =
            Duration.ofHours(24);

    /**
     * Límites permitidos para TTL idle.
     */
    public static final Duration MIN_IDLE =
            Duration.ofMinutes(1);

    public static final Duration MAX_IDLE =
            Duration.ofHours(8);

}