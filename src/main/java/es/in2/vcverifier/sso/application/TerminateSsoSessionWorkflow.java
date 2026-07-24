package es.in2.vcverifier.sso.application;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.sso.application.command.TerminateSsoSessionCommand;
import es.in2.vcverifier.sso.domain.model.DeliveryOutcome;
import es.in2.vcverifier.sso.domain.model.LogoutTarget;
import es.in2.vcverifier.sso.domain.model.LogoutToken;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.BackChannelLogoutNotifierPort;
import es.in2.vcverifier.sso.domain.port.BackchannelLogoutUriPort;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executor;

/**
 * US-06 (Single Logout intra-tenant): orquesta la invalidación local de la sesión SSO
 * (AD-3, ventana 0, AC-02) y el dispatch asíncrono de Back-Channel Logout a los callees
 * (AD-2, AC-03), con auditoría por cada paso (AC-06).
 * <p>
 * Orden estricto (invariante central de la Story): (1) {@code terminateActive} →
 * (2) {@code sso_logout_initiated} → (3) cálculo de callees → (4) entrega al executor
 * asíncrono. El workflow no conoce reintentos ni circuit breaker (SRP): esa responsabilidad
 * vive en {@code BackChannelLogoutDispatcher} (infraestructura).
 * <p>
 * <b>Nota de wiring (Task 7):</b> {@code @Service} se activa en esta task porque
 * {@link BackChannelLogoutNotifierPort} (Task 3) ya tiene implementación real
 * ({@code BackChannelLogoutDispatcher}). El executor pasa del bean genérico por defecto
 * (placeholder de Task 5) al {@code backChannelLogoutExecutor} dedicado (AD-2).
 */
@Slf4j
@Service
public class TerminateSsoSessionWorkflow {

    private final SsoSessionRepositoryPort sessionRepositoryPort;
    private final BackchannelLogoutUriPort backchannelLogoutUriPort;
    private final BackChannelLogoutNotifierPort notifierPort;
    private final SsoAuditPort auditPort;
    private final BackendConfig backendConfig;
    private final Clock clock;
    private final Executor executor;

    public TerminateSsoSessionWorkflow(
            SsoSessionRepositoryPort sessionRepositoryPort,
            BackchannelLogoutUriPort backchannelLogoutUriPort,
            BackChannelLogoutNotifierPort notifierPort,
            SsoAuditPort auditPort,
            BackendConfig backendConfig,
            Clock clock,
            @Qualifier("backChannelLogoutExecutor") Executor executor
    ) {
        this.sessionRepositoryPort = sessionRepositoryPort;
        this.backchannelLogoutUriPort = backchannelLogoutUriPort;
        this.notifierPort = notifierPort;
        this.auditPort = auditPort;
        this.backendConfig = backendConfig;
        this.clock = clock;
        this.executor = executor;
    }

    public void execute(TerminateSsoSessionCommand command) {
        Objects.requireNonNull(command, "command cannot be null");

        Instant now = Instant.now(clock);
        int rows;
        try {
            rows = sessionRepositoryPort.terminateActive(command.sessionId(), command.tenant());
        } catch (Exception ex) {
            // ES-04: fail-closed — invalidación no confirmada, NO se despacha nada.
            log.error("sso_logout_store_error tenant={} sessionId={}...",
                    command.tenant(), prefix8(command.sessionId().getValue()), ex);
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_STORE_ERROR)
                    .tenant(command.tenant())
                    .clientId(command.initiatorClientId())
                    .holderHash(command.holderHash())
                    .sessionId(command.sessionId().getValue())
                    .outcome("error")
                    .reason(ex.getClass().getSimpleName())
                    .correlationId(command.correlationId())
                    .occurredAt(now)
                    .build());
            return;
        }

        if (rows == 0) {
            // EC-01: sesión ya TERMINATED o ausente — idempotente, sin re-dispatch.
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED)
                    .tenant(command.tenant())
                    .clientId(command.initiatorClientId())
                    .holderHash(command.holderHash())
                    .sessionId(command.sessionId().getValue())
                    .outcome("noop")
                    .correlationId(command.correlationId())
                    .occurredAt(now)
                    .build());
            return;
        }

        // AC-01/AC-02: invalidación confirmada — se audita el éxito ANTES de calcular callees.
        // AC-06: holder_hash siempre presente en sso_logout_initiated.
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED)
                .tenant(command.tenant())
                .clientId(command.initiatorClientId())
                .holderHash(command.holderHash())
                .sessionId(command.sessionId().getValue())
                .outcome("success")
                .correlationId(command.correlationId())
                .occurredAt(now)
                .build());

        dispatchBackChannelLogout(command, now);
    }

    private void dispatchBackChannelLogout(TerminateSsoSessionCommand command, Instant now) {
        List<String> clientIds = sessionRepositoryPort.findClientsBySession(command.sessionId(), command.tenant());

        // Resuelto síncronamente en el hilo de la request: BackendConfig.getUrl() depende de
        // RequestContextHolder, no disponible en el hilo del executor asíncrono.
        String issuer = backendConfig.getUrl();

        for (String clientId : clientIds) {
            if (clientId.equals(command.initiatorClientId())) {
                continue; // EC-02: el iniciador no es su propio callee
            }

            Optional<String> backchannelLogoutUri = backchannelLogoutUriPort.resolve(command.tenant(), clientId);
            if (backchannelLogoutUri.isEmpty()) {
                // AC-04: sin canal declarado — skip, no se despacha nada para este callee.
                auditPort.publish(SsoAuditEvent.builder()
                        .eventType(SsoAuditEvent.EventType.BACKCHANNEL_SKIPPED)
                        .tenant(command.tenant())
                        .clientId(clientId)
                        .sessionId(command.sessionId().getValue())
                        .outcome("skipped")
                        .reason("no_backchannel_uri")
                        .correlationId(command.correlationId())
                        .occurredAt(now)
                        .build());
                continue;
            }

            LogoutTarget target = LogoutTarget.of(clientId, backchannelLogoutUri.get());
            LogoutToken token = LogoutToken.of(
                    issuer,
                    clientId,
                    command.sessionId().getValue(),
                    now,
                    UUID.randomUUID().toString()
            );

            // AD-2/AC-03: dispatch asíncrono — no bloquea el hilo de la request del iniciador.
            executor.execute(() -> dispatchToCallee(command, target, token));
        }
    }

    private void dispatchToCallee(TerminateSsoSessionCommand command, LogoutTarget target, LogoutToken token) {
        DeliveryOutcome outcome = notifierPort.notifyLogout(target, token);
        Instant deliveredAt = Instant.now(clock);

        switch (outcome) {
            case DeliveryOutcome.Delivered delivered -> auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.BACKCHANNEL_DELIVERED)
                    .tenant(command.tenant())
                    .clientId(delivered.clientId())
                    .sessionId(command.sessionId().getValue())
                    .outcome("success")
                    .correlationId(command.correlationId())
                    .occurredAt(deliveredAt)
                    .build());
            case DeliveryOutcome.Failed failed -> auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.BACKCHANNEL_FAILED)
                    .tenant(command.tenant())
                    .clientId(failed.clientId())
                    .sessionId(command.sessionId().getValue())
                    .outcome("error")
                    .reason(failed.reason())
                    .correlationId(command.correlationId())
                    .occurredAt(deliveredAt)
                    .build());
        }
    }

    /** NFR-S-551-02: nunca loggear el session_id completo — solo prefijo 8 chars. */
    private static String prefix8(String s) {
        if (s == null) return "null";
        return s.length() <= 8 ? s : s.substring(0, 8);
    }
}
