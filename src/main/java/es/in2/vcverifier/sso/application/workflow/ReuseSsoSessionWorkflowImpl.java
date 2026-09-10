package es.in2.vcverifier.sso.application.workflow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.service.TenantSsoPolicy;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j
@Component
public class ReuseSsoSessionWorkflowImpl implements ReuseSsoSessionWorkflow {

    private static final Duration THROTTLE_INTERVAL = Duration.ofMinutes(1);

    private final TenantSsoConfigPort configPort;
    private final SsoSessionRepositoryPort sessionRepository;
    private final Clock clock;
    private final SsoAuditPort auditPort;
    private final SsoMetricsPort metricsPort;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;
    private final SsoCredentialCipherPort credentialCipherPort;
    private final ObjectMapper objectMapper;

    public ReuseSsoSessionWorkflowImpl(
            TenantSsoConfigPort configPort,
            SsoSessionRepositoryPort sessionRepository,
            Clock clock,
            SsoAuditPort auditPort,
            SsoMetricsPort metricsPort,
            RegisteredClientRepository registeredClientRepository,
            AuthorizationResponseProcessorService authorizationResponseProcessorService,
            SsoCredentialCipherPort credentialCipherPort,
            ObjectMapper objectMapper
    ) {
        this.configPort = configPort;
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditPort = auditPort;
        this.metricsPort = metricsPort;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationResponseProcessorService = authorizationResponseProcessorService;
        this.credentialCipherPort = credentialCipherPort;
        this.objectMapper = objectMapper;
    }

    @Override
    public Result reuse(
            String tenantSlug,
            String ssoCookieValue,
            AuthorizationContext ctx,
            String clientId,
            String correlationId
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
                            .correlationId(correlationId)
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
                                    .holderHash(s.getHolderHash())
                                    .outcome("CROSS_TENANT_BLOCKED")
                                    .correlationId(correlationId)
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
        Long maxAgeSeconds = ctx != null ? ctx.maxAge() : null;
        ReuseDecision decision = policy.evaluate(
                session.getTenant(), tenantSlug, session.getEstablishedAt(),
                clientRegistered, catalog, clientId, maxAgeSeconds
        );

        if (decision == ReuseDecision.REJECT_CATALOG) {
            // AC-03 / US-05: cliente no figura en catálogo SSO → interaction_required
            // AC-05: el contrato de la Story exige explícitamente reason=client_not_eligible
            // en este evento (además de outcome, que ya distinguía el motivo internamente).
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .holderHash(session.getHolderHash())
                            .outcome("CATALOG_REJECTED")
                            .reason("client_not_eligible")
                            .correlationId(correlationId)
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
                            .holderHash(session.getHolderHash())
                            .outcome(decision.name())
                            .correlationId(correlationId)
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        // 6. THROTTLE UPDATE — non-blocking (R-3 / NFR-P-549-01): la respuesta al cliente
        // no espera el UPDATE; el fallo se registra pero no afecta al resultado de reuse.
        // ADR-108/DELTA-02: piggyback de recordClientActivity en el mismo bloque async —
        // recordClientActivity es un upsert idempotente, por lo que el mismo cadencing que
        // el touch de last_used_at es suficiente para mantener sso_session_client al día.
        if (Duration.between(session.getLastUsedAt(), now).compareTo(THROTTLE_INTERVAL) >= 0) {
            CompletableFuture.runAsync(() -> {
                try {
                    sessionRepository.updateLastUsedAt(sessionId, tenantSlug, now);
                    sessionRepository.recordClientActivity(sessionId, tenantSlug, clientId);
                } catch (Exception ex) {
                    log.warn("sso_touch_failed session={} tenant={}", sessionId, tenantSlug, ex);
                }
            });
        }

        // 7. COMPLETE THE AUTHORIZATION — no VP is re-presented on reuse, so the credential
        // claims come from the encrypted snapshot persisted alongside the session row at
        // establishment time (EUD-149: EstablishSsoSessionWorkflow / sso_session.credential_snapshot
        // — replaces the previous non-distributed in-memory cache, which failed closed whenever
        // establishment and reuse landed on different replicas). A missing/undecryptable
        // snapshot (session predates this migration, wrong/rotated key, tampered ciphertext)
        // fails closed to LOGIN_REQUIRED rather than issuing a code without claims.
        JsonNode credentialJson = decryptCredentialSnapshot(tenantSlug, sessionId, session.getCredentialSnapshotCiphertext());
        if (credentialJson == null) {
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .holderHash(session.getHolderHash())
                            .outcome("CREDENTIAL_SNAPSHOT_MISSING")
                            .correlationId(correlationId)
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        // SEC: a code must never be issued for a redirect_uri that isn't registered to THIS
        // client — mirrors CustomAuthorizationRequestConverter#validateRedirectUri, which every
        // other authorization path in this codebase runs before dispatching a redirect. Full-URI
        // match (not just origin): the origin-level allowlist elsewhere is not a substitute.
        String normalizedRequested = OriginNormalizer.normalizeUri(ctx.redirectUri());
        boolean redirectUriRegistered = normalizedRequested != null
                && registeredClient.getRedirectUris().stream()
                        .anyMatch(registered -> normalizedRequested.equals(OriginNormalizer.normalizeUri(registered)));
        if (!redirectUriRegistered) {
            auditPort.publish(
                    SsoAuditEvent.builder()
                            .eventType(SsoAuditEvent.EventType.SSO_REUSE_DENIED)
                            .tenant(tenantSlug)
                            .clientId(clientId)
                            .holderHash(session.getHolderHash())
                            .outcome("REDIRECT_URI_MISMATCH")
                            .correlationId(correlationId)
                            .occurredAt(now)
                            .build()
            );
            return new Result(Result.Status.LOGIN_REQUIRED, null);
        }

        Set<String> scopes = ctx.scope() == null
                ? Set.of()
                : Arrays.stream(ctx.scope().split(" ")).filter(s -> !s.isBlank()).collect(Collectors.toSet());

        String redirectUrl = authorizationResponseProcessorService.issueCodeForReusedSession(
                clientId,
                ctx.redirectUri(),
                scopes,
                ctx.state(),
                ctx.codeChallenge(),
                ctx.codeChallengeMethod(),
                ctx.clientNonce(),
                credentialJson
        );

        // 8. AUDIT
        auditPort.publish(
                SsoAuditEvent.builder()
                        .eventType(SsoAuditEvent.EventType.SSO_SESSION_REUSED)
                        .tenant(tenantSlug)
                        .clientId(clientId)
                        .holderHash(session.getHolderHash())
                        .outcome("REUSED")
                        .correlationId(correlationId)
                        .occurredAt(now)
                        .build()
        );

        metricsPort.recordReuse(tenantSlug, clientId);
        metricsPort.recordOid4vpAvoided(tenantSlug);

        return new Result(Result.Status.ALLOWED, redirectUrl);
    }

    /**
     * EUD-149: descifra el snapshot persistido en {@code sso_session.credential_snapshot}.
     * {@code null} en cualquiera de estos casos (nunca lanza, todos fail-closed en el caller):
     * ciphertext ausente, clave incorrecta/rotada, ciphertext corrupto, o JSON descifrado
     * pero no parseable.
     */
    private JsonNode decryptCredentialSnapshot(String tenant, SsoSessionId sessionId, byte[] ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        return credentialCipherPort.decrypt(tenant, sessionId.getValue(), ciphertext)
                .map(json -> {
                    try {
                        return objectMapper.readTree(json);
                    } catch (JsonProcessingException e) {
                        log.warn("event=sso_credential_snapshot_corrupt tenant={} session={}",
                                tenant, sessionId.getValue().length() <= 8
                                        ? sessionId.getValue() : sessionId.getValue().substring(0, 8));
                        return null;
                    }
                })
                .orElse(null);
    }
}
