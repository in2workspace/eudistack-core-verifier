package es.in2.vcverifier.sso.domain.model;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

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
     * Evalúa si una sesión SSO puede reutilizarse.
     *
     * @param sessionTenant tenant de la sesión activa
     * @param requestTenant tenant del nuevo aplicativo
     * @param sessionEstablishedAt instante de creación de la sesión
     * @param clientEligible si el cliente permite reutilización SSO
     */
    public ReuseDecision evaluate(
            String sessionTenant,
            String requestTenant,
            Instant sessionEstablishedAt,
            boolean clientEligible
    ) {

        // 1. Validación tenant cruzado
        if (sessionTenant != null && requestTenant != null
                && !sessionTenant.equals(requestTenant)) {
            return ReuseDecision.CROSS_TENANT;
        }

        // 2. Cliente no elegible
        if (!clientEligible) {
            return ReuseDecision.CLIENT_NOT_ELIGIBLE;
        }

        // 3. No existe sesión
        if (sessionEstablishedAt == null) {
            return ReuseDecision.NO_SESSION;
        }

        // 4. Sesión expirada
        Instant now = Instant.now(clock);
        Instant expiry = sessionEstablishedAt.plusSeconds(sessionTtlSeconds);

        if (now.isAfter(expiry)) {
            return ReuseDecision.SESSION_EXPIRED;
        }

        // 5. Caso válido
        return ReuseDecision.ALLOWED;
    }
}