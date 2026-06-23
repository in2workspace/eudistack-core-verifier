package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.sso.domain.model.ReuseResult;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Workflow de reutilización silenciosa de sesión SSO.
 * Orquesta dominio + ports sin lógica de infraestructura.
 */
public class ReuseSsoSessionWorkflow {

    private static final Duration THROTTLE_INTERVAL = Duration.ofMinutes(1);

    private final TenantSsoConfigPort configPort;
    private final SsoSessionRepositoryPort sessionRepository;
    private final Clock clock;

    /**
     * Hook de auditoría (puede ser logger, kafka publisher, etc.)
     */
    private final Consumer<String> auditEmitter;

    public ReuseSsoSessionWorkflow(
            TenantSsoConfigPort configPort,
            SsoSessionRepositoryPort sessionRepository,
            Clock clock,
            Consumer<String> auditEmitter
    ) {
        this.configPort = configPort;
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditEmitter = auditEmitter;
    }

    /**
     * Ejecuta el flujo completo de reutilización SSO.
     */
    public ReuseResult execute(
            SsoSessionId sessionId,
            String tenant,
            String clientId
    ) {

        Instant now = Instant.now(clock);

        // =========================================================
        // (1) FETCH CONFIG — FAIL CLOSED ES-02
        // =========================================================
        TenantSsoConfig config = configPort.getByTenant(tenant)
                .orElseThrow(() -> new IllegalStateException(
                        "ES-02: Missing tenant SSO config (fail-closed)"
                ));

        if (!config.ssoEnabled()) {
            return ReuseResult.loginRequired();
        }

        // =========================================================
        // CLIENT ELIGIBILITY (derivado config)
        // =========================================================
        boolean clientEligible = config.eligibleClientIds().isEmpty()
                || config.eligibleClientIds().contains(clientId);

        if (!clientEligible) {
            return ReuseResult.interactionRequired();
        }

        // =========================================================
        // (2) FIND SESSION — FAIL CLOSED ES-01
        // =========================================================
        SsoSession session = sessionRepository
                .findActiveById(sessionId, tenant)
                .orElseThrow(() -> new IllegalStateException(
                        "ES-01: Missing active session (fail-closed)"
                ));

        if (session.isExpired()) {
            return ReuseResult.loginRequired();
        }

        // =========================================================
        // (3) POLICY DECISION
        // =========================================================
        // (simplificado: ya validamos condiciones críticas arriba)
        boolean canReuse = true;

        if (!canReuse) {
            return ReuseResult.loginRequired();
        }

        // =========================================================
        // (4) THROTTLE updateLastUsedAt (EC-03)
        // =========================================================
        if (session.getLastUsedAt() == null ||
                Duration.between(session.getLastUsedAt(), now).compareTo(THROTTLE_INTERVAL) >= 0) {

            sessionRepository.updateLastUsedAt(sessionId, tenant, now);
        }

        // =========================================================
        // (5) AUDIT EVENT
        // =========================================================
        auditEmitter.accept(
                "event=sso_session_reused tenant=" + tenant +
                        " sessionId=" + sessionId +
                        " clientId=" + clientId +
                        " ts=" + now
        );

        // =========================================================
        // (6) RETURN RESULT
        // =========================================================
        return ReuseResult.allowed(session);
    }
}