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
     * Se detecta cambio de tenant entre sesión y solicitud actual.
     */
    CROSS_TENANT,

    /**
     * EC-01: el client_id no existe en el servidor OAuth (RegisteredClientRepository).
     * Gate evaluado en AD-2 condición (1). El workflow lo mapea a {@code login_required}.
     */
    REJECT_UNREGISTERED_CLIENT,

    /**
     * EC-01: sesión inexistente o expirada.
     * El workflow lo mapea a error OIDC {@code login_required}.
     */
    REJECT_SESSION,

    /**
     * EC-01: sesión válida pero el cliente no figura en el catálogo SSO del tenant.
     * El workflow lo mapea a error OIDC {@code interaction_required}.
     */
    REJECT_CATALOG,

    /**
     * AC-09/FR-21: la sesión sigue ACTIVA y dentro del TTL absoluto, pero el cliente ha
     * solicitado explícitamente autenticación fresca ({@code max_age} menor que la
     * antigüedad de la autenticación de la sesión). El workflow lo mapea a
     * {@code login_required} — igual que {@link #REJECT_SESSION}, pero distinguible en
     * auditoría como motivo de rechazo distinto (la sesión en sí es válida).
     */
    REJECT_MAX_AGE
}