package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import static es.in2.vcverifier.sso.domain.model.ReuseDecision.REJECT_CATALOG;
import static es.in2.vcverifier.sso.domain.model.ReuseDecision.REJECT_SESSION;
import static es.in2.vcverifier.sso.domain.model.ReuseDecision.REJECT_UNREGISTERED_CLIENT;

/**
 * Política pura de dominio para decidir si una sesión SSO puede reutilizarse
 * en otro aplicativo dentro del mismo tenant.
 *
 * NO depende de infraestructura, DB ni frameworks.
 */
public final class TenantSsoPolicy {

    private final Clock clock;
    private final long sessionTtlSeconds;

    public TenantSsoPolicy(Clock clock, long sessionTtlSeconds) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.sessionTtlSeconds = sessionTtlSeconds;
    }

    /**
     * AD-2: Evaluación de reutilización con 3 condiciones AND en orden estricto.
     * <ol>
     *   <li>clientRegistered — {@link ReuseDecision#REJECT_UNREGISTERED_CLIENT} si falla (login_required).
     *       Nota: este gate también se aplica upstream en {@code CustomAuthorizationRequestConverter}
     *       (defensa en profundidad); las rutas de producción no alcanzan esta condición si el
     *       cliente no está registrado.</li>
     *   <li>sesión vigente   — {@link ReuseDecision#REJECT_SESSION} si falla (login_required)</li>
     *   <li>catalog.contains — {@link ReuseDecision#REJECT_CATALOG} si falla (interaction_required)</li>
     * </ol>
     *
     * @param sessionTenant        tenant de la sesión activa
     * @param requestTenant        tenant de la solicitud entrante
     * @param sessionEstablishedAt instante de creación de la sesión (null → no hay sesión)
     * @param clientRegistered     true si el client_id existe en el servidor OAuth (pre-computable por el workflow)
     * @param catalog              catálogo SSO del tenant; AC-03: vacío → contains siempre false
     * @param clientId             client_id a evaluar contra el catálogo
     */
    public ReuseDecision evaluate(
            String sessionTenant,
            String requestTenant,
            Instant sessionEstablishedAt,
            boolean clientRegistered,
            TenantSsoCatalog catalog,
            String clientId
    ) {
        Objects.requireNonNull(catalog, "catalog must not be null");

        if (sessionTenant != null && requestTenant != null
                && !sessionTenant.equals(requestTenant)) {
            return ReuseDecision.CROSS_TENANT;
        }

        // AD-2 condición (1): cliente registrado en el servidor OAuth
        if (!clientRegistered) {
            return REJECT_UNREGISTERED_CLIENT;
        }

        // AD-2 condición (2): sesión existente y dentro del TTL absoluto
        if (sessionEstablishedAt == null) {
            return REJECT_SESSION;
        }
        if (Instant.now(clock).isAfter(sessionEstablishedAt.plusSeconds(sessionTtlSeconds))) {
            return REJECT_SESSION;
        }

        // AD-2 condición (3): cliente en el catálogo SSO del tenant
        if (!catalog.contains(clientId)) {
            return REJECT_CATALOG;
        }

        return ReuseDecision.ALLOWED;
    }
}
