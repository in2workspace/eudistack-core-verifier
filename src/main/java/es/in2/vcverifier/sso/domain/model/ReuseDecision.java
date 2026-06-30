package es.in2.vcverifier.sso.domain.model;

/**
 * Resultado de la evaluación de reutilización de sesión SSO.
 */
public enum ReuseDecision {

    /**
     * Existe sesión válida y el cliente es elegible para reutilización.
     */
    ALLOWED,

    /**
     * No existe sesión activa para el holder en el tenant.
     */
    NO_SESSION,

    /**
     * La sesión existe pero ha expirado.
     */
    SESSION_EXPIRED,

    /**
     * El cliente (aplicativo) no está habilitado para reutilización SSO.
     */
    CLIENT_NOT_ELIGIBLE,

    /**
     * Se detecta cambio de tenant entre sesión y solicitud actual.
     */
    CROSS_TENANT
}