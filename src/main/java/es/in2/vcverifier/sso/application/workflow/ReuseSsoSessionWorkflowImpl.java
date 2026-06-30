package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.TenantSsoPolicy;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
public class ReuseSsoSessionWorkflowImpl implements ReuseSsoSessionWorkflow {

    private static final Duration THROTTLE_INTERVAL = Duration.ofMinutes(1);

    private final TenantSsoConfigPort configPort;
    private final SsoSessionRepositoryPort sessionRepository;
    private final Clock clock;
    private final SsoAuditPort auditPort;

    public ReuseSsoSessionWorkflowImpl(
            TenantSsoConfigPort configPort,
            SsoSessionRepositoryPort sessionRepository,
            Clock clock,
            SsoAuditPort auditPort
    ) {
        this.configPort = configPort;
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditPort = auditPort;
    }

    @Override
    public Result reuse(
            String tenantSlug,
            String ssoCookieValue,
            AuthorizationContext ctx,
            String clientId
    ) {
        Instant now = Instant.now(clock);

        // 1. CONFIG
        TenantSsoConfig config = configPort.getByTenant(tenantSlug)
                .orElseThrow(() -> new IllegalStateException(
                        "ES-02: Missing tenant SSO config (fail-closed)"
                ));

        if (!config.ssoEnabled()) {
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        // 2. SESSION ID FROM COOKIE
        if (ssoCookieValue == null || ssoCookieValue.isBlank()) {
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        SsoSessionId sessionId = SsoSessionId.of(ssoCookieValue);

        // 3. SESSION LOOKUP — separar fallo de BD de sesión no encontrada
        Optional<SsoSession> maybeSession;
        try {
            maybeSession = sessionRepository.findActiveById(sessionId, tenantSlug);
        } catch (Exception ex) {
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_PERSIST_ERROR)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .outcome("REPOSITORY_FAILURE")
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        if (maybeSession.isEmpty()) {
            // AC-04: detectar intento cross-tenant antes de denegar
            sessionRepository.findById(sessionId)
                    .filter(s -> !tenantSlug.equals(s.getTenant()))
                    .ifPresent(s -> auditPort.publish(
                            SsoAuditEvent.builder()
                                    .eventType(SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT)
                                    .tenant(tenantSlug)
                                    .clientId(clientId)
                                    .outcome("CROSS_TENANT_BLOCKED")
                                    .occurredAt(now)
                                    .build()
                    ));
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        SsoSession session = maybeSession.get();

        // 4. IDLE TTL — comprobación combinada (abs TTL ya filtrada en SQL)
        if (!session.isValid(now, config.ttl().idle())) {
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        // 5. CLIENT ELIGIBILITY — usa TenantSsoPolicy para evaluar elegibilidad
        boolean clientEligible = config.eligibleClientIds().isEmpty()
                || config.eligibleClientIds().contains(clientId);

        TenantSsoPolicy policy = new TenantSsoPolicy(clock, config.ttl().absolute().toSeconds());
        ReuseDecision decision = policy.evaluate(
                session.getTenant(), tenantSlug, session.getEstablishedAt(), clientEligible
        );

        if (decision == ReuseDecision.CLIENT_NOT_ELIGIBLE) {
            // AC-03: auditar denegación por cliente no elegible
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .outcome("CLIENT_NOT_ELIGIBLE")
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.INTERACTION_REQUIRED, null);
        }

        // 6. THROTTLE UPDATE
        if (Duration.between(session.getLastUsedAt(), now).compareTo(THROTTLE_INTERVAL) >= 0) {
            sessionRepository.updateLastUsedAt(sessionId, tenantSlug, now);
        }

        // 7. AUDIT
        auditPort.publish(
                SsoAuditEvent.builder()
                        .eventType(SsoAuditEvent.EventType.SSO_SESSION_REUSED)
                        .tenant(tenantSlug)
                        .clientId(clientId)
                        .outcome("REUSED")
                        .occurredAt(now)
                        .build()
        );

        return new Result(Result.Status.ALLOWED, null);
    }
}
