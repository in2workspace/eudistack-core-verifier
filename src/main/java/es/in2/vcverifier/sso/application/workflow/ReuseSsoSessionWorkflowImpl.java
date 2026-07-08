package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.service.TenantSsoPolicy;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Component
public class ReuseSsoSessionWorkflowImpl implements ReuseSsoSessionWorkflow {

    private static final Duration THROTTLE_INTERVAL = Duration.ofMinutes(1);

    private final TenantSsoConfigPort configPort;
    private final SsoSessionRepositoryPort sessionRepository;
    private final Clock clock;
    private final SsoAuditPort auditPort;
    private final RegisteredClientRepository registeredClientRepository;

    public ReuseSsoSessionWorkflowImpl(
            TenantSsoConfigPort configPort,
            SsoSessionRepositoryPort sessionRepository,
            Clock clock,
            SsoAuditPort auditPort,
            RegisteredClientRepository registeredClientRepository
    ) {
        this.configPort = configPort;
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditPort = auditPort;
        this.registeredClientRepository = registeredClientRepository;
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
        Optional<TenantSsoConfig> configOpt = configPort.getByTenant(tenantSlug);
        if (configOpt.isEmpty() || !configOpt.get().ssoEnabled()) {
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        SsoSessionTtl ttl = configPort.resolveTtl(tenantSlug);

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
        if (!session.isValid(now, ttl.idle())) {
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        // 5. POLICY AD-2: (1) cliente registrado en OAuth server, (2) sesión vigente (abs TTL),
        //                  (3) cliente en catálogo SSO del tenant — EC-01
        boolean clientRegistered = registeredClientRepository.findByClientId(clientId) != null;
        TenantSsoCatalog catalog = configPort.resolveEligibleClients(tenantSlug);

        TenantSsoPolicy policy = new TenantSsoPolicy(clock, ttl.absolute().toSeconds());
        ReuseDecision decision = policy.evaluate(
                session.getTenant(), tenantSlug, session.getEstablishedAt(),
                clientRegistered, catalog, clientId
        );

        if (decision == ReuseDecision.REJECT_CATALOG) {
            // AC-03 / US-05: cliente no figura en catálogo SSO → interaction_required
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .outcome("CATALOG_REJECTED")
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.INTERACTION_REQUIRED, null);
        }

        if (decision != ReuseDecision.ALLOWED) {
            // REJECT_SESSION, REJECT_UNREGISTERED_CLIENT, CROSS_TENANT u otro motivo → login_required
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .outcome(decision.name())
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        // 6. THROTTLE UPDATE — non-blocking (R-3 / NFR-P-549-01): la respuesta al cliente
        // no espera el UPDATE; el fallo se registra pero no afecta al resultado de reuse.
        if (Duration.between(session.getLastUsedAt(), now).compareTo(THROTTLE_INTERVAL) >= 0) {
            CompletableFuture.runAsync(() -> {
                try {
                    sessionRepository.updateLastUsedAt(sessionId, tenantSlug, now);
                } catch (Exception ex) {
                    log.warn("sso_touch_failed session={} tenant={}", sessionId, tenantSlug, ex);
                }
            });
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
