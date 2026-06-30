package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
public class ReuseSsoSessionWorkflowImpl implements ReuseSsoSessionWorkflow {

    private static final Logger log = LoggerFactory.getLogger(ReuseSsoSessionWorkflowImpl.class);
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
            return new Result(
                    Result.Status.LOGIN_REQUIRED,
                    null
            );
        }

        // 2. SESSION ID FROM COOKIE
        if (ssoCookieValue == null || ssoCookieValue.isBlank()) {
            return new Result(
                    Result.Status.LOGIN_REQUIRED,
                    null
            );
        }

        SsoSessionId sessionId = SsoSessionId.of(ssoCookieValue);

        Optional<SsoSession> found;
        try {
            found = sessionRepository.findActiveById(sessionId, tenantSlug);
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

        if (found.isEmpty()) {
            try {
                sessionRepository.findById(sessionId).ifPresent(existingSession -> {
                    if (!tenantSlug.equals(existingSession.getTenant())) {
                        auditPort.publish(
                                SsoAuditEvent.builder()
                                        .eventType(SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT)
                                        .tenant(tenantSlug)
                                        .clientId(clientId)
                                        .outcome("CROSS_TENANT_ATTEMPT")
                                        .occurredAt(now)
                                        .build()
                        );
                    }
                });
            } catch (Exception ignored) {
                // la detección cross-tenant es best-effort
            }
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        SsoSession session = found.get();

        // 3. VALIDITY (absolute + idle TTL)
        SsoSessionTtl ttl = configPort.resolveTtl(tenantSlug);

        if (!session.isValid(now, ttl.idle())) {
            return new Result(
                    Result.Status.LOGIN_REQUIRED,
                    null
            );
        }

        // 4. CLIENT ELIGIBILITY

        boolean clientEligible = config.eligibleClientIds().isEmpty()
                || config.eligibleClientIds().contains(clientId);

        if (!clientEligible) {
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .outcome("CLIENT_NOT_ELIGIBLE")
                            .occurredAt(now)
                            .build()
            );
            return new Result(
                    Result.Status.INTERACTION_REQUIRED,
                    null
            );
        }

        // 5. THROTTLED TOUCH (non-blocking — R-3 / NFR-P-549-01)
        if (session.getLastUsedAt() == null ||
                Duration.between(session.getLastUsedAt(), now).compareTo(THROTTLE_INTERVAL) >= 0) {

            Thread.ofVirtual()
                    .uncaughtExceptionHandler((t, ex) ->
                            log.warn("Non-blocking touch failed for tenant={}: {}", tenantSlug, ex.getMessage()))
                    .start(() -> sessionRepository.updateLastUsedAt(sessionId, tenantSlug, now));
        }

        // 6. AUDIT
        auditPort.publish(
                SsoAuditEvent.builder()
                        .eventType(SsoAuditEvent.EventType.SSO_SESSION_REUSED)
                        .tenant(tenantSlug)
                        .clientId(clientId)
                        .outcome("REUSED")
                        .occurredAt(now)
                        .build()
        );

        // 7. RETURN
        return new Result(Result.Status.ALLOWED, null);
    }
}